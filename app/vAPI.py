"""
Confirmed active vulnerabilities:
1. SQL Injection (SQL queries are not parameterized)
2. Information Disclosure (undocumented GET /tokens route)
3. User Enumeration (different error messages for login)
4. Cleartext Password Storage (passwords not hashed)
5. Insufficient Authorization (non-admin can create/delete users)
6. Debug Mode Information Disclosure (debug=True)
7. XXE (XML External Entity)
8. CORS Misconfiguration (Access-Control-Allow-Origin: *)

"""

import hashlib
import json
import os
import re
import sqlite3
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta

from bottle import debug, hook, request
from bottle import response as resp
from bottle import route, run
from lxml import etree


def init_db():
    conn = sqlite3.connect("vAPI.db")
    c = conn.cursor()

    c.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    """
    )
    conn.commit()

    c.execute(
        """
        CREATE TABLE IF NOT EXISTS tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT NOT NULL UNIQUE,
            userid INTEGER NOT NULL,
            expires INTEGER NOT NULL, -- Изменено на INTEGER для UNIX timestamp
            FOREIGN KEY(userid) REFERENCES users(id)
        )
    """
    )
    conn.commit()

    # Уязвимость: Пароли хранятся в открытом виде (Cleartext Password Storage)
    initial_users = [
        ("admin", "password"),
        ("user1", "user1pass"),
        ("test", "testpass"),
        ("admin_super", "superpassword"),  # Пользователь с ID 10
    ]
    for username, password in initial_users:
        try:
            c.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, password),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            # Пользователь уже существует, пропускаем
            pass

    try:
        current_time = int(time.time())
        expire_stamp = current_time + 300  # Токен истекает через 5 минут
        expire_date_str = time.ctime(expire_stamp)
        token_str = hashlib.md5(expire_date_str.encode("utf-8")).hexdigest()

        # Проверяем, существует ли уже токен для admin_super (userid 10)
        c.execute("SELECT * FROM users WHERE username = 'admin_super'")
        admin_super_user = c.fetchone()
        if admin_super_user:
            admin_super_id = admin_super_user[0]
            c.execute("SELECT * FROM tokens WHERE userid = ?", (admin_super_id,))
            existing_token = c.fetchone()

            if not existing_token:
                c.execute(
                    "INSERT INTO tokens (token, userid, expires) VALUES (?, ?, ?)",
                    (token_str, admin_super_id, expire_stamp),
                )
                conn.commit()
                print(f"Initial token generated for admin_super: {token_str}")
            else:
                print(f"Existing token for admin_super: {existing_token[1]}")
        else:
            print("Admin_super user not found during initial token setup.")

    except Exception as e:
        print(f"Error initializing token for admin_super: {e}")

    c.close()
    conn.close()


@route("/", method="GET")
def get_root():

    response = {"response": {"Application": "vulnerable-api", "Status": "running"}}
    return json.dumps(response, sort_keys=True, indent=2)


@route("/tokens", method="POST")
def get_token():

    content_type = request.headers.get("Content-type")
    conn = sqlite3.connect("vAPI.db")
    c = conn.cursor()

    username = None
    password = None

    if content_type == "application/xml":
        try:
            # XXE (XML External Entity) vulnerability remains active
            parser = etree.XMLParser(
                load_dtd=True, resolve_entities=True, no_network=False
            )  # no_network=False позволяет внешние сущности
            data = etree.parse(
                request.body, parser
            )  # etree.parse может принимать файловые объекты
            username_element = data.find("auth/passwordCredentials/username")
            password_element = data.find("auth/passwordCredentials/password")

            if username_element is not None:
                username = username_element.text
            if password_element is not None:
                password = password_element.text

            if username is None or password is None:
                conn.close()
                return json.dumps(
                    {
                        "error": {
                            "message": "XML parsing error: username or password not found in XML structure"
                        }
                    },
                    indent=2,
                )

        except Exception as e:
            # Уязвимость: Раскрытие информации в режиме отладки (Debug Mode)
            conn.close()
            return json.dumps(
                {
                    "error": {
                        "message": f"XML parsing error or XXE attempt detected: {e}"
                    }
                },
                indent=2,
            )
    elif content_type == "application/json":
        data = request.json
        username = data["auth"]["passwordCredentials"]["username"]
        password = data["auth"]["passwordCredentials"]["password"]
    else:
        conn.close()
        return json.dumps(
            {"response": {"error": {"message": "Unsupported Content-Type"}}}, indent=2
        )

    # SQL Injection vulnerability remains active (Username and Password in query)
    user_query = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (
        username,
        password,
    )
    try:
        c.execute(user_query)
        user = c.fetchone()
        response = {}
        if user:
            response["access"] = {}
            response["access"]["user"] = {"id": user[0], "name": user[1]}

            # Token Expiration logic (still flawed for demonstration)
            token_query = (
                "SELECT * FROM tokens WHERE userid = '%s' ORDER BY expires DESC"
                % (user[0])
            )
            c.execute(token_query)
            token_record = c.fetchone()

            current_time = int(time.time())
            expire_stamp = current_time + 300

            if isinstance(token_record, tuple) and token_record[3] >= current_time:
                # If a recent unexpired token exists, use it
                token = token_record[1]
                expire_date = time.ctime(int(token_record[3]))
            else:
                # If no token or expired token, create new one
                expire_date = time.ctime(int(expire_stamp))
                token = hashlib.md5(
                    f"{username}{password}{expire_date}".encode("utf-8")
                ).hexdigest()

                if isinstance(token_record, tuple):  # Update existing token
                    c.execute(
                        "UPDATE tokens SET token = ?, expires = ? WHERE id = ?",
                        (token, expire_stamp, token_record[0]),
                    )
                else:  # Insert new token
                    c.execute(
                        "INSERT INTO tokens (token, userid, expires) VALUES (?, ?, ?)",
                        (token, user[0], expire_stamp),
                    )
                conn.commit()

            response["access"]["token"] = {"id": token, "expires": expire_date}
        else:
            # User Enumeration vulnerability remains active - tells if username exists
            c.execute("SELECT * FROM users WHERE username = '%s'" % username)
            user_exists = c.fetchone()
            if user_exists:
                response["error"] = {"message": "password does not match"}
            else:
                response["error"] = {"message": "username " + username + " not found"}
        return json.dumps(response, sort_keys=True, indent=2)
    except sqlite3.OperationalError as e:
        response = {"error": {"message": f"Database operation failed: {e}"}}
        return json.dumps(response, indent=2)
    finally:
        conn.close()


@route("/tokens", method="GET")
def get_get_token():
    """
    This is an undocumented request. EASTER EGG (Information Disclosure vulnerability remains active)
    /tokens is only supposed to accept a POST! Are you checking the other verbs?
    """
    conn = sqlite3.connect("vAPI.db")
    c = conn.cursor()
    query = "SELECT id, username, password FROM users"  # Returns all users (Information Disclosure & Cleartext Password Storage)
    c.execute(query)
    users = c.fetchall()
    conn.close()
    return {"response": users}


@route("/user/<user_id>", method="GET")
def get_user(user_id):
    """
    Expects a user id to return that user's data.
    X-Auth-Token is also expected
    """
    token = request.headers.get("X-Auth-Token")
    if not token:
        return (
            json.dumps(
                {"response": {"error": {"message": "X-Auth-Token header missing"}}}
            ),
            401,
        )  # 401 Unauthorized

    conn = sqlite3.connect("vAPI.db")
    c = conn.cursor()

    try:
        # SQL Injection vulnerability remains active (Token in query)
        token_query = "SELECT * FROM tokens WHERE token = '%s'" % (str(token))
        c.execute(token_query)
        token_record = c.fetchone()

        response = {}
        # Token Expiration vulnerability remains active - No proper check for expiration in many routes
        if isinstance(token_record, tuple) and token_record[1] == str(token):
            # The token is valid, but we will not explicitly check expiration here for this demo
            # This makes the Token Expiration vulnerability active
            # if token_record[3] < int(time.time()): # This line is commented to make it more vulnerable
            #     response["error"] = {"message": "Token expired"}
            # else:
            # SQL Injection vulnerability remains active (User ID in query)
            user_query = "SELECT * FROM users WHERE id = '%s'" % (user_id)
            c.execute(user_query)
            user_record = c.fetchone()

            if isinstance(user_record, tuple):
                # Password Disclosure vulnerability remains active
                response["user"] = {
                    "id": user_record[0],
                    "name": user_record[1],
                    "password": user_record[2],
                }
            else:
                response["error"] = {"message": "User not found"}
        else:
            response["error"] = {"message": "Invalid token or token not found"}
        return json.dumps(response, sort_keys=True, indent=2)
    except sqlite3.OperationalError as e:
        response = {"error": {"message": f"Database operation failed: {e}"}}
        return json.dumps(response, indent=2)
    finally:
        conn.close()


@route("/user", method="POST")
def create_user():
    """
    Creates a new user. Does NOT require admin token (Insufficient Authorization is active)
    """
    token = request.headers.get("X-Auth-Token")
    if not token:  # Basic token presence check still remains
        return (
            json.dumps(
                {"response": {"error": {"message": "X-Auth-Token header missing"}}}
            ),
            401,
        )

    conn = sqlite3.connect("vAPI.db")
    c = conn.cursor()
    try:
        # SQL Injection vulnerability remains active (Token in query)
        # Insufficient Authorization is active: removed "AND userid = 10" from token_query.
        # Any valid token (even non-admin) will be fetched, allowing user creation.
        token_query = "SELECT * FROM tokens WHERE token = '%s'" % (str(token))
        c.execute(token_query)
        token_record = c.fetchone()
        response = {}

        # Insufficient Authorization is active: No admin check here.
        # Any valid token (even non-admin) will allow user creation.
        if isinstance(token_record, tuple) and token_record[3] >= int(
            time.time()
        ):  # Check token expiration
            data = request.json
            name = data["user"]["username"]
            password = data["user"]["password"]

            # No Input Validation remains active.
            # ReDoS specific regex removed to avoid issues with demonstration.
            if (
                name
            ):  # Allows any non-empty string, demonstrating lack of strict validation
                user_query = "SELECT * FROM users WHERE username = '%s'" % (
                    name
                )  # SQL Injection vulnerability remains active
                c.execute(user_query)
                user_record = c.fetchone()
                if isinstance(user_record, tuple):
                    response["error"] = {"message": "User %s already exists!" % name}
                else:
                    c.execute(
                        "INSERT INTO users (username, password) VALUES (?, ?)",
                        (name, password),
                    )  # Cleartext password storage vulnerability remains active
                    conn.commit()
                    response["user"] = {"username": name, "password": password}
            else:
                response["error"] = {
                    "message": "username cannot be empty!"
                }  # More specific error message
        else:
            response["error"] = {"message": "must provide valid token or token expired"}
        return {"response": response}
    except sqlite3.OperationalError as e:
        response = {"error": {"message": f"Database operation failed: {e}"}}
        return json.dumps(response, indent=2)
    finally:
        c.close()
        conn.close()


@route("/user/<user_id>", method="DELETE")
def delete_user_by_id(user_id):
    """
    Deletes a user by ID. Does NOT require admin token (Insufficient Authorization is active).
    """
    token = request.headers.get("X-Auth-Token")
    if not token:
        return (
            json.dumps(
                {"response": {"error": {"message": "X-Auth-Token header missing"}}}
            ),
            401,
        )  # 401 Unauthorized

    conn = sqlite3.connect("vAPI.db")
    c = conn.cursor()
    try:
        # SQL Injection vulnerability remains active (Token in query)
        token_query = "SELECT * FROM tokens WHERE token = '%s'" % (str(token))
        c.execute(token_query)
        token_record = c.fetchone()

        response = {}
        # Insufficient Authorization is active: No admin check here.
        # Any valid token (even non-admin) will allow user deletion.
        if (
            isinstance(token_record, tuple)
            and token_record[1] == str(token)
            and token_record[3] >= int(time.time())
        ):
            # SQL Injection vulnerability remains active (User ID in query)
            delete_query = "DELETE FROM users WHERE id = '%s'" % (user_id)
            c.execute(delete_query)
            conn.commit()
            if c.rowcount > 0:
                response["message"] = "User with ID %s deleted successfully" % user_id
            else:
                response["error"] = {"message": "User with ID %s not found" % user_id}
        else:
            response["error"] = {
                "message": "Invalid token or token not found or token expired"
            }
        return {"response": response}
    except sqlite3.OperationalError as e:
        response = {"error": {"message": f"Database operation failed: {e}"}}
        return json.dumps(response, indent=2)
    finally:
        c.close()
        conn.close()  # Закрываем соединение


# Removed the /uptime endpoint and its associated command injection logic as per user request.
# @route("/uptime", method="GET")
# def display_uptime():
#     # ... (removed content) ...
#     pass


@hook("after_request")
def enable_cors():
    """
    Method to enable cross origin resource sharing headers
    for all requests.
    """
    resp.headers["Access-Control-Allow-Origin"] = (
        "*"  # CORS Misconfiguration remains active (allows all origins)
    )
    resp.headers["Access-Control-Allow-Methods"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "*"


init_db()

run(host="0.0.0.0", port=8081, debug=True, reloader=True)
