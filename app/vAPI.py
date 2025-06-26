"""
This API interacts with a user and token database.
The code is written to exemplify common API security vulnerabilities
1. No input validation
2. SQL queries are not parameterized
3. No real error handling
4. Errors that are handled give too much information
4. Tokens have an expiration date, but do not expire
5. Token string is generated with an md5 of the expire datetime string
6. Passwords are not hashed in the database
7. There is an *undocumented* GET that returns the user database
"""

import hashlib
import json
import os
import re
import sqlite3
import subprocess  # Added for safe command execution
import time
import xml.etree.ElementTree as ET

from bottle import debug, hook, request
from bottle import response as resp
from bottle import route, run
from lxml import etree


@route("/", method="GET")
def get_root():
    """
    Give default message for a GET on root directory.
    """
    response = {"response": {"Application": "vulnerable-api", "Status": "running"}}
    return json.dumps(response, sort_keys=True, indent=2)


@route("/tokens", method="POST")
def get_token():
    """
    User needs to get an auth token before actioning the database
    """
    content_type = request.headers.get("Content-type")
    if content_type == "application/xml":
        try:
            # LXML is vulnerable to XXE, etree is vulnerable to Billion Laughs
            # So just have etree try to parse it just to watch it die
            # In Python 3, request.body is a file-like object, read its content.
            # ET.parse can handle bytes directly.
            ET.parse(request.body)
        except Exception as e:  # Changed to 'as e' for Python 3 best practice
            # But etree will throw an exception for XXE, so ignore that
            pass
        # force unsafe external entity parsing
        parser = etree.XMLParser(load_dtd=True, resolve_entities=True)
        # etree.parse can also handle file-like objects for XML,
        # but if issues, consider etree.fromstring(request.body.read())
        data = etree.parse(request.body, parser)
        username = data.find("passwordCredentials").find("username").text
        password = data.find("passwordCredentials").find("password").text
    else:
        data = request.json
        username = data["auth"]["passwordCredentials"]["username"]
        password = data["auth"]["passwordCredentials"]["password"]
    conn = sqlite3.connect("vAPI.db")
    c = conn.cursor()
    # no data validation
    # no sql parameterization (SQL Injection vulnerability remains)
    user_query = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (
        username,
        password,
    )
    c.execute(user_query)
    user = c.fetchone()
    response = {}
    if user:
        response["access"] = {}
        response["access"]["user"] = {"id": user[0], "name": user[1]}
        # make sure to get most recent token in database, because we arent
        # removing them...
        token_query = (
            "SELECT * FROM tokens WHERE userid = '%s' ORDER BY expires DESC" % (user[0])
        )
        c.execute(token_query)
        token_record = c.fetchone()
        if isinstance(token_record, tuple):
            if token_record[3] < int(time.time()):
                # token has expired. create new one that expires 5 minutes
                # after creation
                expire_stamp = int(time.time() + 300)
                expire_date = time.ctime(int(expire_stamp))
                # Python 3: hashlib.md5 expects bytes, so encode the string
                token = hashlib.md5(expire_date.encode("utf-8")).hexdigest()
                # we'll parameterize this one because we need this serious
                # functionality
                c.execute(
                    "INSERT INTO tokens (token, userid, expires) VALUES (?, ?, ?)",
                    (token, user[0], expire_stamp),
                )
                conn.commit()
                response["access"]["token"] = {"id": token, "expires": expire_date}
            else:
                # recent token hasn't expired. use same one.
                expire_date = time.ctime(int(token_record[3]))
                response["access"]["token"] = {
                    "id": token_record[1],
                    "expires": expire_date,
                }
        else:
            # no token exists. create one that expires in 5 minutes
            expire_stamp = int(time.time() + 300)
            expire_date = time.ctime(int(expire_stamp))
            # Python 3: hashlib.md5 expects bytes, so encode the string
            token = hashlib.md5(expire_date.encode("utf-8")).hexdigest()
            # we'll parameterize this one because we need this serious
            # functionality
            c.execute(
                "INSERT INTO tokens (token, userid, expires) VALUES (?, ?, ?)",
                (token, user[0], expire_stamp),
            )
            conn.commit()
            response["access"]["token"] = {"id": token, "expires": expire_date}
    else:
        # let's do another look up so we can return helpful info for failure
        # cases (User Enumeration vulnerability remains)
        c.execute("SELECT * FROM users WHERE username = '%s'" % username)
        user = c.fetchone()
        if user:
            response["error"] = {"message": "password does not match"}
        else:
            response["error"] = {"message": "username " + username + " not found"}
    conn.close()

    # Python 3: return json.dumps(response) directly, not {json.dumps(response)}
    return json.dumps(response)


@route("/tokens", method="GET")
def get_get_token():
    """
    this is an undocumented request. EASTER EGG (Information Disclosure vulnerability remains)
    /tokens is only supposed to accept a POST! Are you checking the other verbs?
    """
    conn = sqlite3.connect("vAPI.db")
    c = conn.cursor()
    query = "SELECT * FROM users"  # Returns all users (Information Disclosure vulnerability remains)
    c.execute(query)
    users = c.fetchall()
    return {"response": users}


@route("/user/<user:re:.*>", method="GET")
def get_user(user):
    """
    Expects a user id to return that user's data.
    X-Auth-Token is also expected
    """
    token = request.headers.get("X-Auth-Token")
    conn = sqlite3.connect("vAPI.db")
    c = conn.cursor()
    user_query = "SELECT * FROM users WHERE id = '%s'" % (
        user
    )  # SQL Injection vulnerability remains
    c.execute(user_query)
    user_record = c.fetchone()
    token_query = "SELECT * FROM tokens WHERE token = '%s'" % (
        str(token)
    )  # SQL Injection vulnerability remains
    c.execute(token_query)
    token_record = c.fetchone()
    c.close()
    response = {}
    # you'll notice we don't actually check the token expiration date (Token Expiration vulnerability remains)
    if isinstance(token_record, tuple):
        if isinstance(user_record, tuple):
            if token_record[2] == user_record[0]:
                response["user"] = {}
                response["user"]["id"] = user_record[0]
                response["user"]["name"] = user_record[1]
                response["user"]["password"] = user_record[
                    2
                ]  # Password Disclosure vulnerability remains
            else:
                response["error"] = {"message": "the token and user do not match!"}
        else:
            response["error"] = {"message": "user id " + user + " not found"}
    else:
        response["error"] = {"message": "token id " + str(token) + " not found"}
    conn.close()

    return {"response": response}


@route("/user", method="POST")
def create_user():
    token = request.headers.get("X-Auth-Token")
    conn = sqlite3.connect("vAPI.db")
    c = conn.cursor()
    token_query = "SELECT * FROM tokens WHERE token = '%s' AND userid = 10" % (
        str(token)
    )  # SQL Injection vulnerability remains
    c.execute(token_query)
    token_record = c.fetchone()
    response = {}
    if isinstance(token_record, tuple):
        data = request.json
        name = data["user"]["username"]
        password = data["user"]["password"]
        # catastrophically bad regex (ReDoS vulnerability remains)
        match = "([a-z]+)*[0-9]"
        m = re.search(match, name)
        if m:
            user_query = "SELECT * FROM users WHERE username = '%s'" % (
                name
            )  # SQL Injection vulnerability remains
            c.execute(user_query)
            user_record = c.fetchone()
            if isinstance(user_record, tuple):
                response["error"] = {"message": "User %s already exists!" % name}
            else:
                c.execute(
                    "INSERT INTO users (username, password) VALUES (?, ?)",
                    (name, password),
                )  # Cleartext password storage vulnerability remains
                conn.commit()
                response["user"] = {"username": name, "password": password}
        else:
            response["error"] = {
                "message": "username {0} invalid format, check documentation!".format(
                    name
                )
            }
    else:
        response["error"] = {"message": "must provide valid admin token"}

    c.close()
    return {"response": response}


@route("/uptime", method="GET")
@route("/uptime/<flag>", method="GET")
def display_uptime(flag=None):
    # !!! MAJOR CHANGE: PREVENTS COMMAND INJECTION !!!
    # Replaced os.popen with subprocess.check_output to safely execute commands.
    # This prevents an attacker from injecting arbitrary commands via the 'flag' parameter.
    if flag:
        command = ["uptime", "-" + flag]
    else:
        command = ["uptime"]
    try:
        output = subprocess.check_output(command).decode("utf-8").strip()
    except subprocess.CalledProcessError as e:
        output = f"Error executing command: {e.stderr.decode('utf-8').strip()}"
    except FileNotFoundError:
        output = "Error: 'uptime' command not found."

    response = {"response": {"Command": " ".join(command), "Output": output}}
    return json.dumps(response, sort_keys=True, indent=2)


@hook("after_request")
def enable_cors():
    """
    Method to enable cross origin resource sharing headers
    for all requests.
    """
    resp.headers["Access-Control-Allow-Origin"] = "*"  # CORS Misconfiguration remains
    resp.headers["Access-Control-Allow-Methods"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "*"


debug(True)  # Debug mode enabled (Information Disclosure vulnerability remains)
run(host="0.0.0.0", port=8081, reloader=True)
