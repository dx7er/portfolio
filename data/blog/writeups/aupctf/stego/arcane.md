---
title: AUPCTF'23 - Stegnography - Arcane
date: '2023-06-26'
tags: ['ctf', 'stegnography', 'aupctf', 'writeup', 'arcane', 'Jinx', 'magic-bytes-fixing']
draft: false
summary: Arcane was a good stego challenge. The file was named `arcane.exe` however it was linux executable. The challenge was to find the flag hidden in the files extracted after executing the file.
---

## Challenge Description

In the city of Piltover, chaos reigns supreme as Jinx, the mischievous troublemaker, roams the streets. Armed with her deadly arsenal and a wicked grin, she sets the city ablaze with her explosive antics. navigate Jinx's twisted mind, decipher her puzzles, and outsmart her at every turn to uncover the hidden flag. Will you be able to tame the chaos and triumph over Jinx's mischief?

[arcane.exe](https://aupctf.s3.eu-north-1.amazonaws.com/arcane.exe)

## Solution

So, the first thing I normally do when downloading the file, is run `file` command to check the type of file it is:

```bash
file arcane.exe
```

![Arcane](/static/writeups/aupctf/stego/arcane.png)

We can see, that the file is a linux executable, let's give it executable permissions and run it:

```bash
chmod +x arcane.exe
./arcane.exe
```

![Arcane](/static/writeups/aupctf/stego/arcane2.png)

Weird enough, the binary ran `7z` to extract some contents and then exited. Let's check the contents of the directory:

![Arcane](/static/writeups/aupctf/stego/arcane3.png)

Well, we can see a new folder has been created called `arcane`, let's check the content within it

![Arcane](/static/writeups/aupctf/stego/arcane4.png)

Using the file manager (`nautilus`), to check the files

![Arcane](/static/writeups/aupctf/stego/arcane5.png)

Now, in CTFs, whenever I'm presented with files, i often run a simple command to seperate all the different ones and then check them individually. So, let's do that:

```bash
for i in $(ls); do md5sum $i; done | sort
```

![Arcane](/static/writeups/aupctf/stego/arcane6.png)

Now, what this will do, is it will; at the end give the names of all the files whose `md5sum` is different from the rest. Now, we can see we have 3 different files we can check

```sh
img
869.jpg
786_dba.jpg
```

Let's check the `img` file first:
```sh
file img
```

![Arcane](/static/writeups/aupctf/stego/arcane7.png)

It says `data`, the next thing I normally do, is check the `magic bytes` of the file, to see if they match the file type. So, let's do that:

```sh
xxd img | head
```

![Arcane](/static/writeups/aupctf/stego/arcane8.png)

Now, we can see that the `magic bytes` are `89 50 58 47`, which somewhat correspond to a `PNG` image. However, the actual `magic bytes` of a `PNG` image are `89 50 4E 47 0D 0A 1 A 0A`. So, let's fix that using hexedit

![Arcane](/static/writeups/aupctf/stego/arcane9.png)

Now, pressing `F2` to save and `CTRL+X` to exit hexedit, we re-run the file command

![Arcane](/static/writeups/aupctf/stego/arcane10.png)

Opening the file, we're greeted with a plain-white canvas

![Arcane](/static/writeups/aupctf/stego/arcane11.png)

Let's try opening this in `stegsolve` and see if we can find anything

![Arcane](/static/writeups/aupctf/stego/arcane12.png)

> Looking for password? Look no further than the name of the character - it holds the key you seek.

Well, the challenge description says `jinx`, so let's try that. But, where do we need to enter the password?

Remember, we got 2 more files, that actually checked out, and both of them were JPEG images, let's try steghide on both of them:

```sh
steghide extract -sf <file_name>
```

![Arcane](/static/writeups/aupctf/stego/arcane13.png)

Let's try catting the file:

![Arcane](/static/writeups/aupctf/stego/arcane14.png)

Flag: `aupCTF{JinxTheArcaneTrickster}`
