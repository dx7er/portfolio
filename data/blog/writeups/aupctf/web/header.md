---
title: AUPCTF'23 - Web - Header
date: '2023-06-25'
tags: ['ctf', 'web', 'aupctf', 'writeup', 'django', 'http-headers']
draft: false
summary: 
---

## Challenge Description

Carefully analyze the source code

[Click Here](https://challs.aupctf.live/header/)

## Solution:

By visiting the website, we're greeted with the following source code:

```py
def headar_easy(request):
    if request.META.get('HTTP_GETFLAG') == 'yes':
        context = {
            'flag': '[REDACTED]',
        }

        return render(request, 'aa/flag.html', context)
    
    return render(request, 'aa/index.html')
```

Now, let's firstly understand what `request.META` is. According to the [docs](https://docs.djangoproject.com/en/3.2/ref/request-response/#django.http.HttpRequest.META):

> A dictionary containing all available HTTP headers. Available headers depend on the client and server

Now, we can understand that we just need to append the HTTP Header called `HTTP_GETFLAG` and set it's value to yes. Simple as that, but, the only catch is, when sending the header, we do not need to append `HTTP_` to the header as Django does it for us. So, we can simply send the header `GETFLAG` with the value `yes`. To also prove this, according the the [docs](https://docs.djangoproject.com/en/3.2/ref/request-response/#django.http.HttpRequest.META), we can see

```py
- HTTP_ACCEPT – Acceptable content types for the response.
- HTTP_ACCEPT_ENCODING – Acceptable encodings for the response.
- HTTP_ACCEPT_LANGUAGE – Acceptable languages for the response.
- HTTP_HOST – The HTTP Host header sent by the client.
- HTTP_REFERER – The referring page, if any.
- HTTP_USER_AGENT – The client’s user-agent string.
```

So, we can see that the header `HTTP_HOST` is actually `Host` and `HTTP_REFERER` is `Referer`. So, we can simply send the header `GETFLAG` with the value `yes` and get the flag. To check, we will firstly utilize burp suite, and then use python to automate it

![Header](/static/writeups/aupctf/web/header_1.png)

Now, let's automate it using python:

```py
import requests

url = "https://challs.aupctf.live/header/"
r = requests.get(
	url,
	headers = {
		"GETFLAG" : "yes"
	}
)

print(f"Flag: {r.text}")
```

Flag: `aupCTF{cust0m-he4d3r-r3qu3st}`

---