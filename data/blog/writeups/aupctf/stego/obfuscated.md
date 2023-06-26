---
title: AUPCTF'23 - Stegnography - Obfuscated
date: '2023-06-26'
tags: ['ctf', 'stegnography', 'aupctf', 'writeup', 'obfuscated', 'bit-shifting', 'magic-bytes-fixing']
draft: false
summary: In this challenge, we had to swap every two bits with each other in order to get the flag.
---

## Solution

We were given a file named [flag.jpg](https://aupctf.s3.eu-north-1.amazonaws.com/flag.jpg). Let's check the file type using `file` command:

![Obfuscated](/static/writeups/aupctf/stego/obfuscated.png)

Now, since the file is `data`, let's check the magic bytes of the file

```sh
xxd flag.jpg | head -n 1
```

![Obfuscated](/static/writeups/aupctf/stego/obfuscated2.png)

Looking up the actual magic bytes of a jpeg image

![Obfuscated](/static/writeups/aupctf/stego/obfuscated3.png)

Now, we can see that the magic bytes of the image given to us

```py
ff 8d ff 0e 00 01 a4 64 94 64 00 10
```

are different from the actual magic bytes of a jpeg image

```py
ff d8 ff e0 00 10 4a 46 49 46 00 01
```

However, it makes sense. We can see, that only the bits are shifted with one another, so we can write a simple script to do that for us:

```py:obfuscated-solver.py
import binascii

def swap_bits(hex_string):
    swapped_hex = ''
    for i in range(0, len(hex_string), 2):
        hex_pair = hex_string[i:i+2]
        binary = bin(int(hex_pair, 16))[2:].zfill(8)
        swapped_binary = binary[4:] + binary[:4]
        swapped_hex_pair = hex(int(swapped_binary, 2))[2:].zfill(2)

        swapped_hex += swapped_hex_pair

    return swapped_hex

with open('flag.jpg', 'rb') as file:
    hex_data = binascii.hexlify(file.read()).decode()

swapped_hex_data = swap_bits(hex_data)

with open('updated-flag.jpg', 'wb') as file:
    file.write(binascii.unhexlify(swapped_hex_data))

```

Now, once we run the script, we can see a new file called `updated-flag.jpg` is created with the flag

![Obfuscated](/static/writeups/aupctf/stego/obfuscated4.png)

Flag: `aupCTF{sw4p3d_w0w453?5422asd!1}`
