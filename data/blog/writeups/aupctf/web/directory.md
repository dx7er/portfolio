---
title: AUPCTF'23 - Web - Directory
date: '2023-06-25'
tags: ['ctf', 'web', 'aupctf', 'writeup', 'brute-force', 'directory-searching']
draft: false
summary: Directory was a simple directory searching challenge in which we had to find the flag by bruteforcing the directories and reading the innerhtml content.
---

## Challenge Description

The flag is buried in one of the directory

[Click Here](https://challs.aupctf.live/dir/)

## Solution

By visiting the website, we're greeted with the following page:

![Directory](/static/writeups/aupctf/web/dir_land.png)

Now, we can see that the total number of directories is `1000`. Manually testing each will be a pain, let's automate it. In order to do so, we need to find an error or a condition on the basis of which we'll check if we've found the flag or not. Let's visit a directory:

![Directory](/static/writeups/aupctf/web/dir_1.png)

Now, since we have our benchmark, we will write the following python script, using `threading` ofcourse to speed up the process:

```py
import requests
import re
import threading

url = "https://challs.aupctf.live/dir"


def _post(_dir):
	r = requests.get(f"{url}/page/{_dir}")

	if "no flag" not in r.text.lower():
		print(f"[{_dir}] Flag found: ", end='')
		flag = re.findall('<h2>The flag is: (.*?)</h2>', r.text)[0]
		print(flag)

pages = [int(i) for i in range(1, 1001)]

print("[*] Bruteforcing...")
threads = []
for page in pages:
	t = threading.Thread(target=_post, args=(page,))
	threads.append(t)
	t.start()

for t in threads:
	t.join()
```

Running the script, we get the following output:

```js
[*] Bruteforcing...
[712] Flag found: aupCTF{d1r3ct0r13s-tr1v14l-fl4g}
```

---