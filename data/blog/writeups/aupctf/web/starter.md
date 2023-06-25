---
title: AUPCTF'23 - Web - Starter
date: '2023-06-25'
tags: ['ctf', 'web', 'aupctf', 'writeup', 'source-code-analysis']
draft: false
summary: Starter was a very easy web challenge in which flag could be found using basic source code analysis.
---

## Challenge Description

mera tu sir chakra raha tum dekh lo ... [random](https://challs.aupctf.live/starter/)

## Solution

By visiting the website, we're greeted with the following page:

![Starter](/static/writeups/aupctf/web/starter_land.png)

Now, if we simply right click drag, we see the following

![Starter](/static/writeups/aupctf/web/starter_drag.png)

So, we can see that the flag is in the source code. Let's take a look at the source code.

```html
<!DOCTYPE html>
<html>
<head>
    <title>Random</title>
        <style>
            p {
                text-align: center;
                font-size: 7em;
                color: rgba(247, 255, 183, 0.123);
            }
            span {
                font-size: 3em;
            }
            .word {
                display: flex;
                flex-wrap: wrap;
                justify-content: center;
                align-items: center;
            }
            .letter {
                font-size: 24px;
                font-weight: bold;
                color: #6f5fff7e;
                text-shadow: 1px 1px 1px #000;
                position: relative;
                margin: 10px;
            }
        </style>
    </head>
    <body>
        <p>Search for the Flag</p>
        <p>In the Source Code</p>
        <div class="box">
            <div class="word">
                <span id="letter1">a</span>
                <span id="letter2">u</span>
                <span id="letter3">p</span>
                <span id="letter4">C</span>
                <span id="letter5">T</span>
                <span id="letter6">F</span>
                <span id="letter7">{</span>
            </div>
            <div class="word">
                <span id="letter8">w</span>
                <span id="letter9">4</span>
                <span id="letter10">5</span>
                <span id="letter11">n</span>
                <span id="letter12">'</span>
                <span id="letter13">t</span>
                <span id="letter14">-</span>
                <span id="letter15">t</span>
                <span id="letter16">h</span>
                <span id="letter17">4</span>
                <span id="letter18">7</span>
                <span id="letter19">-</span>
                <span id="letter20">h</span>
                <span id="letter21">4</span>
                <span id="letter22">r</span>
                <span id="letter23">d</span>
                <span id="letter24">-</span>
                <span id="letter25">r</span>
                <span id="letter26">1</span>
                <span id="letter27">g</span>
                <span id="letter28">h</span>
                <span id="letter29">7</span>
            </div>
            <div class="word">
                <span id="letter30">}</span>
            </div>
        </div>
        
        <script>
            // Position each letter randomly on the screen
            var letters = document.querySelectorAll('.box .word span');
            for (var i = 0; i < letters.length; i++) {
                var letter = letters[i];
                letter.style.position = 'absolute';
                letter.style.top = Math.floor(Math.random() * (window.innerHeight - letter.offsetHeight)) + "px";
                letter.style.left = Math.floor(Math.random() * (window.innerWidth - letter.offsetWidth)) + "px";
            }
        </script>
    </body>
</html>    
```

Now, there are multiple ways to solve this, we'll take a look at four different approaches

### Approach 1: Manual cleaning

Well, in the heat of the moment, no one opts for automating every single task and sometimes, it's just easier to do it manually. So, let's do that. Firstly, I will extract all the lines that contain the flag.

```html
<span id="letter1">a</span>
<span id="letter2">u</span>
<span id="letter3">p</span>
<span id="letter4">C</span>
<span id="letter5">T</span>
<span id="letter6">F</span>
<span id="letter7">{</span>
<span id="letter8">w</span>
<span id="letter9">4</span>
<span id="letter10">5</span>
<span id="letter11">n</span>
<span id="letter12">'</span>
<span id="letter13">t</span>
<span id="letter14">-</span>
<span id="letter15">t</span>
<span id="letter16">h</span>
<span id="letter17">4</span>
<span id="letter18">7</span>
<span id="letter19">-</span>
<span id="letter20">h</span>
<span id="letter21">4</span>
<span id="letter22">r</span>
<span id="letter23">d</span>
<span id="letter24">-</span>
<span id="letter25">r</span>
<span id="letter26">1</span>
<span id="letter27">g</span>
<span id="letter28">h</span>
<span id="letter29">7</span>
<span id="letter30">}</span>
```

Now, being a keyboard ninja, I will use Sublime Text and multiline cursors (Ctrl+Alt+Up/Down) to select all the span tags and then delete them. This leaves us with the following:

```html
aupCTF{w45n't-th47-h4rd-r1gh7}
```

### Approach 2: Using bash

Firstly, sending a basic `cURL` request to fetch the entire page, then, I utilized `grep` to extract all the `span` tags and then `sed` to remove the tags and `tr` to remove the newlines. This leaves us with the following:

```bash
$ curl --silent https://challs.aupctf.live/starter/ | grep -o '<span.*</span>' | sed 's/<[^>]*>//g' | tr -d $'\n'
```

![Starter-Bash-Flag](/static/writeups/aupctf/web/starter_bash_flag.png)

### Approach 3: Using Javascript/Console

Another approach we can take is utilizing basic `javascript` to extract the `innerHTML` from all the `span` tags and then joining them together. This can be done by opening the console and running the following:

```js
var spanElements = document.querySelectorAll('span');
var spanContents = [];
spanElements.forEach((span) => {spanContents.push(span.innerHTML);});
console.log(`Flag: ${spanContents.join('')}`);
```

![Starter-JS-Flag](/static/writeups/aupctf/web/starter_js.png)

### Approach 4: Using Python

The final automated apporach will be using python. We will use the `requests` library to fetch the page and then use `re` to extract all the `span` tags and then join them together. This can be done by running the following:

```py
import requests
import re

url = "https://challs.aupctf.live/starter/"
r = requests.get(url)
elems = re.findall('">(.*?)</span>', r.text)
print(f"Flag: {''.join(elems)}")
```

![Starter-Python-Flag](/static/writeups/aupctf/web/starter_python.png)

---
