---
title: AUPCTF'23 - Web - Time Heist
date: '2023-06-25'
tags: ['ctf', 'web', 'aupctf', 'writeup', 'archive.org', 'snapshot', 'wayback-machine']
draft: false
summary: Time Heist was a simple web challenge in which we had to find the flag by looking at a tag in a website which was later deleted.
---

## Challenge Description

use your time travel skills to recover the hidden flag

[Click Here](https://iasad.me/tags/)

## Solution

Now, the challenge description is a clear hint that we need to use the [Wayback Machine](https://archive.org/web/). So, we visit the website and get the following snapshots of the given url

![Time Heist](/static/writeups/aupctf/web/time_heist.png)

Now, visting the first snapshot, we get the following page:

![Time Heist](/static/writeups/aupctf/web/time_heist_1.png)

We can see that there is a tag `flag` in the page. Let's visit it:

[URL](https://web.archive.org/web/20230528105831/https://iasad.me/tags/flag/)

![Time Heist](/static/writeups/aupctf/web/time_heist_2.png)

On opening this, we get the following page:

![Time Heist](/static/writeups/aupctf/web/time_heist_3.png)

Now, let's inspect the source code, we get the following flag:

![Time Heist](/static/writeups/aupctf/web/time_heist_4.png)

Flag: `aupCTF{y0u-ar3-4-tru3-t1m3-tr4v3l3r}`