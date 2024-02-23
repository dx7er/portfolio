---
title: Writing and Deploying Pwn challenges
date: '2024-02-23'
tags: ['dev-notes', 'pwn', 'docker', 'deployment']
draft: false
summary: Creating a pwn challenge from scratch, and deploying it remotely using Docker.
---

# Introduction

This blog post will cover all the basics on how you can develop pwn challenges and how to deploy them using docker so that they will listen on port and allow remote connections.

Same concept can be used to deploy any python (crypto/misc/jail escapes) challenges to remote.

## Challenge Development

Let's consider the following source code:

```c:main.c
#include <stdio.h>

__attribute__((constructor))
void __constructor__(){
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    alarm(0x10);
}

void win() {
    system("cat flag.txt");
}

void vuln() {
    char buffer[0x10];
    gets(buffer);
}

int main(int argc, char* argv) {
    vuln();
}
```

Now, consider this source code. I won't go through where the vulnerability exists, and how we can exploit it. However, the one function called `__constructor__` is pretty important. What this will do, is allow for buffering, so when this binary is hosted to receive connection through a socket, it's IO will be unbuffered and will allow for `stdin`, `stdout` and `stderr` to be served over a socket. And alarm will automatically send `SIGALARM` to the binary after `n` seconds, i.e. in our case `0x10` seconds.

For every pwn chal to you create, make sure to just copy paste this `__constructor__` function, or set buffering.

The following table contains all the information we need to know about the `gcc` flags for pwn:

| flag | Description |
| --- | --- |
| -fno-stack-protector | Disable Stack Canary |
| -no-pie | Disables PIE on the final executable and also sets RELRO to partial |
| -zexecstack | Marks the stack as executable |
| -Wl,-z,norelro | Sets no RELRO |

> NOTE: PIE must be disabled for RELRO to be partial.

For ease of use, I made a Makefile for me a while back, it doesn't follow good practises or anything, but gets the job done, so:

```makefile:Makefile
CC   := gcc
IN   := main.c
OUT  := main
BASE := $(CC) $(IN) -o $(OUT) -w

all:
    # compile with all protections
    $(BASE); $(MAKE) checksec
no:
    # compile with no protections
    $(BASE) -fno-stack-protector -no-pie -zexecstack -Wl,-z,norelro; $(MAKE) checksec
nocanary:
    # compile without a canary
    $(BASE) -fno-stack-protector; $(MAKE) checksec
nopie:
    # compile without PIE (also sets partial relro)
    $(BASE) -no-pie; $(MAKE) checksec
nonx:
    # compile without nx
    $(BASE) -zexecstack; $(MAKE) checksec
nopiecanary:
    # compile without pie and canary
    $(BASE) -fno-stack-protector -no-pie; $(MAKE) checksec
nocanarynx:
    # compile without canary and nx
    $(BASE) -fno-stack-protector -zexecstack; $(MAKE) checksec

checksec:
    checksec $(OUT)
```

> NOTE: In case you get `*** missing seperator. Stop.` error, convert all the indentations to use tabs instead of spaces.

The use is pretty easy. All you need to do is modify the `IN` and `OUT` variables, and then, if you want to compile a binary that has no protections:

```bash
make no

# You can change the argument to be any Make target that you want to build.
## If I want to build a binary that has NX disable
make nonx
```

## Remote Deployment

When developing challenges for [Pakistan Cyber Security Challenge](https://github.com/AirOverflow/PCC-23-Challs), I made a simple and easy to use Docker Image, and I fixed a few bugs that I found in the image. You can find it on [Github](https://github.com/TheFlash2k/my-containers/tree/main/pwn-chal) or on [Dockerhub](https://hub.docker.com/r/theflash2k/pwn-chal)

Now, in order to deploy this challenge, we can use `theflash2k/pwn-chal:latest`. For C++ binaries, I made a seperate image with a `cpp` tag i.e. `theflash2k/pwn-chal:cpp` and similarly the python one is (python 3.8 and ubuntu 20.04) `theflash2k/pwn-chal:python`. All three images follow the same syntax and same set of environment variables are required to setup the image.

> I have read up on pwnred.jail and is pretty amazing, but with my already developed plugins, it was becoming a pain to integrate, so I just created my own image ;-;.

For the particular challenge that we wrote earlier, we can deploy it using the following simple Dockerfile:

```dockerfile:Dockerfile
FROM theflash2k/pwn-chal:latest

ENV CHAL_NAME="main"
COPY ${CHAL_NAME} .
COPY flag.txt .
```

> Internally, by default; pwn-chal listens on port 8000. You can read up the documentation on Github/Dockerhub.

To build this image, I often write a simple script called `docker-build.sh` that contains the following content:

```bash:docker-build.sh
#!/bin/bash

docker build -t my-first-pwn-chal .
```

And, another script called `run.sh` that contains the following:

```bash:run.sh
#!/bin/bash

docker run -it --rm --name my-first-pwn-chal --hostname pwn-chal -p8000:8000 my-first-pwn-chal
```

Now, the final folder structure that I maintain looks something like this:

```bash
/src/
    ├── docker-build.sh
    ├── Dockerfile
    ├── flag.txt
    ├── main
    ├── main.c
    ├── Makefile
    └── run.sh
```

I'm currently working on ARM challenges and will update this blog accordingly. However, for Kernel-based challenges' development & deployment, you can look up [Papadoxie](https://papadoxie.github.io/Blog/Making%20a%20Kernel%20CTF%20%28PUCon%2724%20pwn%20CTF%29/)'s guide. He has explained quite a lot of stuff.
