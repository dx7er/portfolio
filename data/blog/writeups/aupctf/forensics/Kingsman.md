---
title: AUPCTF'23 - Forensics - Kingsman
date: '2023-06-25'
tags: ['ctf', 'forensics', 'aupctf', 'writeup', 'kingsman', 'john-the-ripper', 'hashcat', 'custom-wordlist', 'brute-force']
draft: false
summary: Kingsman was a fairly simple, yet a time consuming challenge in which we had to crack a password protected 7z file.
---

## Challenge Description

Welcome to Kingsman, the world's most elite intelligence agency where we pride ourselves on our cutting-edge technology. However, it appears that our highly sophisticated security system has been breached by an unknown hacker. Even our state-of-the-art AI, Merlin, has failed to protect our system against this intrusion. Your mission, if you choose to accept it, is to use your advanced decryption skills to bypass our highly flawed password policy and uncover the secrets that lie within. Get ready for the ultimate test of your intelligence as you embark on this daring mission to decrypt the hidden message that awaits. Only by cracking the code will you be able to claim your victory and prove yourself worthy of becoming a Kingsman agent. So, are you ready to accept this challenge?

The password requirements are as follows:

The first character must be a digit.
The second character must be a special character. `" ! @ $ % ^ & * ( ) "`
A pet name should follow the special character.
An uppercase letter comes next.
Finally, a lowercase letter.

Remember, Your objective is to crack the encryption and reveal the hidden message. **-- John**

[Download](https://aupctf.s3.eu-north-1.amazonaws.com/encrypted.7z)

## Solution

Now, in order to solve this, we needed to firstly write a simple script that would generate all the possible combinations of the password. But one thing was pretty vague, `a pet name`? The admins were kind enough to later provide us with a simple [list](https://aupctf.s3.eu-north-1.amazonaws.com/pets.txt) of pets. So, utilizing that, I wrote the following script:

```py
import itertools

def generate_wordlist():
    digits = '0123456789'
    special_chars = '" !@$%^&*()'
    pet_names = ['max', 'charlie', 'cooper', 'jack', 'rocky', 'bear', 'roxy', 'lucy', 'duke', 'toby']
    uppercase_letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    lowercase_letters = 'abcdefghijklmnopqrstuvwxyz'

    wordlist = []

    for digit, special_char, pet_name, uppercase, lowercase in itertools.product(digits, special_chars, pet_names, uppercase_letters, lowercase_letters):
        wordlist.append(digit + special_char + pet_name + uppercase + lowercase)

    return wordlist

wordlist = generate_wordlist()

# Print the wordlist or write it to a file
with open('wordlist.txt', 'w') as file:
        file.write('\n'.join(wordlist))

```

Now, since we have a wordlist, what will we do now? Well, we can solve it using `John The Ripper` or `Hashcat`. I'll be using `Hashcat` for this challenge. So, let's get started.

Firstly, we need to convert the `.7z` into a format that hashcat will understand. I used the following [tool](https://github.com/philsmd/7z2hashcat/) to convert the `.7z` file into a `hash` file that hashcat could understand. 

```bash
7z2hashcat64-1.9.exe encrypted.7z  > hash
```

![hash](/static/writeups/aupctf/forensics/kingsman_hash.png)

```bash
$7z$2$19$0$$8$dd5e3a9508fa8fd30000000000000000$1392961481$320$315$7eb91aa9f103cc54eb0304bb7fb5ade2511d453c026f7ced7bc55bb3a5ade4f63c51f6d9b4846f5038e0ece15cb9a57f88908f49925cf3bfd0e812d40fc0278920c90ed4b4ca478045f0d1e2e94ea9842d91afa224bd387a0f528805cb12d1763b804fc6ab916b3986c66093a2cdee996ba4593f758b382bb8c5f7ec0b82d4ed44f480067aae5f7d10a1c04041d089eb0bb56ce53bf6c4afb02a62950ae6aabfddc80cfd668c748cacee0aea38abc3b340aeed2dafcc0654ef79623fea83b2426fd790641fdfd7a37706513f7d49db69cdfa89cf954b8e800d2cdb92df2df74510b04184f9353446d5ace6165dfd0a18892d66c8166ffc33b6cbc1f3ff7b477fbdf4eca73f5314620cbacabcf004958756618a2ab45720514f5734ddc534d062a3aba1e2488dad763a109ca23258d1db21ca75b22720759e7dfcea724d72b523$419$00
```

Now, once we have the hash and the wordlist, we will use the following command to crack the hash

```bash
hashcat -m 11600 -a 3 hash wordlist.txt
```

Now, after a few mins, we get the password `9"roxyFk`. Once done, we can use the password to extract the flag from the `.7z` file.

![cracked](/static/writeups/aupctf/forensics/kingsman_cracked.png)

> NOTE:
Many people were struggling on this challenge because in the description, the author said `" ! @ $ % ^ & * ( ) "`, and many people were not taking into account the `"` and the actual password did consist of it.

![un7z](/static/writeups/aupctf/forensics/kingsman_un7z.png)

Now, we a `flag.txt` in our current directory, we will get the flag:

![flag](/static/writeups/aupctf/forensics/kingsman_flag.png)

Flag: `aupCTF{j0hncr4ck5pa55w0rd5!}`
