---
title: HTB - Cyber Apocalypse 2024 - Rev - Follow The Path
date: '2024-03-14'
tags: ['rev', 'htb', 'cyber-apocalypse', 'self-decryption']
draft: false
summary: Using x64dbg to analyze a self-decrypting program and manually extracting the flag.
---

## Challenge Description

![alt text](/static/writeups/htb-cyberapocalypse/image-11.png)

## Solution

Follow The Path was a medium reversing challenge that had a self-decrypting code, where each logic block was being unwrapped after `0x31` instructions. I did it manually, but after talking to [72ghoul](https://github.com/hexamine22/ctfs/tree/main/Cyber-Apocalypse-2024), he wrote a pretty amazing unicorn script (I know I should really learn Unicorn by now). Well anyways, I really loved this challenge.

So, let's start by analyzing the binary in IDA:

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  FILE *v3; // rax
  char v5[128]; // [rsp+40h] [rbp-98h] BYREF

  puts("Please enter the flag");
  v3 = _acrt_iob_func(0);
  common_fgets<char>(v5, 127LL, v3);
  JUMPOUT(0x140001000LL);
}
```

Now, the code was simply jumping to an offset on the stack, the disassembly showed: `jmp [rsp+0D8h+var_A0]`. I set-up a breakpoint here, and ran the program

![alt text](/static/writeups/htb-cyberapocalypse/image-18.png)

The program asks for the flag, and I know the format is `HTB{.*}`, so to get started, I sent the flag: `HTB{testflagtrustme}`

Now, stepping into the address, where the program was jumping to

![alt text](/static/writeups/htb-cyberapocalypse/image-19.png)

Now, one thing that I noticed:

```asm
loc_7FF6BBD0101E:                       ; CODE XREF: .text:00007FF6BBD01015↑j
inc     rcx
lea     r8, loc_7FF6BBD01039
xor     rdx, rdx

loc_7FF6BBD0102B:                       ; CODE XREF: .text:00007FF6BBD01037↓j
xor     byte ptr [r8+rdx], 0DEh
inc     rdx
cmp     rdx, 39h ; '9'
jnz     short loc_7FF6BBD0102B
```

The `loc_7FF6BBD0101E` label was loading the data at `loc_7FF6BBD01039` to `r8` register. Then emptying `rdx`; setting it up as a counter variable. The next label i.e. `loc_7FF6BBD0102B` was simply xorring the instructions at `r8+rdx` with `0xDE`. And kept xorring until rdx was `0x39`. So, I understood that it was simply decrypting the instructions at runtime. I ran the code `0x39` times:

![alt text](/static/writeups/htb-cyberapocalypse/image-20.png)

However, IDA wasn't happy with this. For this, I switched to `x64dbg`. The first thing I did was find the actually logic jump and setup a breakpoint there:

![alt text](/static/writeups/htb-cyberapocalypse/image-21.png)

Now, after stepping into the call, I found the logic in the disassembly

![alt text](/static/writeups/htb-cyberapocalypse/image-22.png)

After running the instructions `0x39` times, I saw the instructions build up slowly in x64dbg

![alt text](/static/writeups/htb-cyberapocalypse/image-23.png)

Here I saw four instructions that really stood out to me:

```asm
00007FF6BBD01007   | 49:81F0 C4000000   | xor r8,C4                                |
00007FF6BBD0100E   | 49:81F8 8C000000   | cmp r8,8C                                |

00007FF6BBD01040   | 49:81F0 55000000   | xor r8,55                                |
00007FF6BBD01047   | 49:81F8 01000000   | cmp r8,1                                 |
```

After simply checking in python:

![alt text](/static/writeups/htb-cyberapocalypse/image-24.png)

Now, I was pretty certain that this is the flag. So, I simply checked each instruction; step-by-step. But since my `r8` would be different, and `xor r8, N` would result in a different `r8`. So on each `cmp` instruction, I had to change the value. One more problem that I had, I did not the size of the actual flag. So I had to go through each of these steps a few time ;-;. Here's the final script that got me the flag:

```py:solve.py

elem = [
    0xC4^0x8c,
    0x55^0x1,
    0x1b^0x59,
    0x95^0xEE,
    0xD5^0xA6,
    0x9^0x3A,
    0xc^0x60,
    0x3c^0x7a,
    0xC7^0x98,
    0x1b^0x7f,
    0xb^0x38,
    0xF8^0xBB,
    0xCB^0x99,
    0xDF^0x86,
    0x28^0x58,
    0x11^0x65,
    0x8c^0xbd,
    0x80^0xb0,
    0xBF^0xF1,
    0xAE^0x83,
    0xF9^0xC8,
    0x26^0x55,
    0x95^0xCA,
    0xE9^0x82,
    0x97^0xA6,
    0x60^0xE,
    0x9D^0xF9,
    0x87^0xb3,
    0x52^0xD,
    0xE5^0x86,
    0x53^0x63,
    0x2E^0x1E,
    0xF6^0x9A,
    0x4^0x5B,
    0x78^0x11,
    0x22^0x17,
    0x85^0xEB,
    0x3E^0x4A,
    0xF^0x50,
    0x4D^0x7C,
    0x4^0x70,
    0xC8^0xB5
]

flag = "".join([chr(i) for i in elem])
print(flag)
```

![alt text](/static/writeups/htb-cyberapocalypse/image-25.png)

Overall, a pretty fun an interesting challenge. I should've solved this with Unicorn, but idk. ;-;
