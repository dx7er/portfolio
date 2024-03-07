---
title: PCC '23 - Rev - [etyBtloB]
date: '2023-12-07'
tags: ['ctf', 'rev', 'pcc', 'bit-shifting', 'elf', 'shift', 'reversing']
draft: false
summary: Performing FU on a binary to fix it and run it to find the flag
---

## Challenge Description

![Alt text](/static/writeups/pcc23/image-18.png)

## Solution

This binary was a per-user binary; meaning each user had a different flag in their binaries. Starting the instance; we're greeted with a simple web-page from where we can download the binary

![download-page](/static/writeups/pcc23/image-19.png)

Now, this challenge was uploaded as part of the PCC qualifiers but no one was able to solve it. However it was pretty easy. Running the binary:

![Alt text](/static/writeups/pcc23/image-20.png)

Well, let's try and look at the strings of the binary:

![strings](/static/writeups/pcc23/image-21.png)

One thing that is weird; everything is rotated, one line looked like it made sense; reversing it:

![gcc](/static/writeups/pcc23/image-22.png)

Well, it matches `GCC`, but `HCD`. Oh, It looks like each byte is shifted-by-1 and the entire binary is currently reversed. Let's firstly un-reverse the binary and then look at the bytes to actually confirm our theory.

```py:solve.py
#!/usr/bin/env python3

with open('boltbyte', 'rb') as f:
    _in = f.read()

_in = _in[::-1] # Reversing

with open('final', 'wb') as f:
    f.write(_in)
```

![Alt text](/static/writeups/pcc23/image-23.png)

Now, let's look the binary's bytes:

![Alt text](/static/writeups/pcc23/image-24.png)

Well, this confirmed our theory, every even byte is shifted by-1, so let's write a simple script to fix the binary:

```py:solve.py
#!/usr/bin/env python3

with open('boltbyte', 'rb') as f:
    _in = f.read()

data = _in[::-1] # Reversing

buf = b"" 
for i in range(0, len(data)):
    buf += ((data[i] - 1) % 256 if i % 2 == 0 else data[i]).to_bytes(1, 'little')

with open('final', 'wb') as f:
    f.write(buf)
```

After running the script and running `file` on file:

![Alt text](/static/writeups/pcc23/image-25.png)

Overall, I know it was a bit of a guessy challenge, but ;-;. I hope you enjoyed the writeup.
