---
title: AUPCTF'23 - Web - SQLi 2
date: '2023-06-25'
tags: ['ctf', 'web', 'aupctf', 'sqli', 'login-bypass']
draft: false
summary: 
---

## Solution

We're given the following URL to work with:

```js
https://challs.aupctf.live/sqli-2/
```

Upon visiting the URL, we're greeted with a login page:

![Login Page](/static/writeups/aupctf/web/sqli2.png)

Now, since we already know that the challenge is of `SQLi`, we will try and use the same payload from [SQLi-1](/blog/writeups/aupctf/web/sqli-1/).
And... it works!

![Login Page](/static/writeups/aupctf/web/sqli2_flag.png)

Now, using the same script we wrote in [SQLi-1](/blog/writeups/aupctf/web/sqli-1/) and just changing the URL, we get the flag
Flag: `aupCTF{m3d1um-sql-1nj3cti0n}`