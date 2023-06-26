---
title: AUPCTF'23 - Stegnography - Deep
date: '2023-06-26'
tags: ['ctf', 'stegnography', 'aupctf', 'writeup', 'deep', 'deep-sound', 'audio-forensics', 'iron-man']
draft: false
summary: A combination of OSINT and Audio Forensics, this challenge was a fun one. We had to find the flag hidden in the audio file, extracting a simple exe and running it, performing OSINT to get the flag
---

## Solution

We are given a [wav](https://aupctf.s3.eu-north-1.amazonaws.com/truefan.wav) file. Given the name of the challenge, we know a software called [DeepSound](http://jpinsoft.net/DeepSound/)

> DeepSound is a steganography tool and audio converter that hides secret data into audio files. The application also enables you to extract secret files directly from audio files or audio CD tracks.

So, let's open the file in DeepSound
On opening the file, we are presented with a screen asking for a password

![Deep](/static/writeups/aupctf/stego/deep.png)

The admin gave us the following hint

> looking for password ? well thats the iconic dialogue of iron man

Being a Marvel fan, I knew the dialogue was `I am Iron Man`. So, let's try that as `iamironman`

![Deep](/static/writeups/aupctf/stego/deep2.png)

Now, going to the `Documents` folder, we have a file called `marvel.exe`, simply running it

![Deep](/static/writeups/aupctf/stego/deep3.png)

We are greeted with a question:

> How much does Morgan Starks love her dad? [number]

Well, all the marvel fans know the answer is `3000`

![Deep](/static/writeups/aupctf/stego/deep4.png)

> What is the full form of J.A.R.V.I.S.?

Well, this was a simple google search, `Just A Rather Very Intelligent System`

![Deep](/static/writeups/aupctf/stego/deep5.png)

> What is the full form of AI that replaced J.A.R.V.I.S.?

Again, a simple google search, `Friday` and the full form is `Female Replacement Intelligent Digital Assistant Youth`

![Deep](/static/writeups/aupctf/stego/deep6.png)

```txt
Congratulations! You are a true Marvel Nerd like Me ;/
Flag format: iron man first appearance year underscore last appearance year in movies
```

Now, I knew the first Iron Man movie came out in 2008 and the last movie was `Avengers: Endgame` which came out in 2019. So, the flag is `2008_2019`

Flag: `aupctf{2008_2019}`

All in all, the challenge was fun but involved more OSINT rather than stego.