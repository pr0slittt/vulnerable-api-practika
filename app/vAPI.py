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
            expires INTEGER NOT NULL,
            FOREIGN KEY(userid) REFERENCES users(id)
        )
    """
    )
    conn.commit()

    initial_users = [
        ("admin", "password"),
        ("user1", "user1pass"),
        ("test", "testpass"),
        ("admin_super", "superpassword"),
    ]
    for username, password in initial_users:
        try:
            c.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, password),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            pass

    try:
        current_time = int(time.time())
        expire_stamp = current_time + 300
        expire_date_str = time.ctime(expire_stamp)
        token_str = hashlib.md5(expire_date_str.encode("utf-8")).hexdigest()

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
            parser = etree.XMLParser(
                load_dtd=True, resolve_entities=True, no_network=False
            )
            data = etree.parse(request.body, parser)
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

            token_query = (
                "SELECT * FROM tokens WHERE userid = '%s' ORDER BY expires DESC"
                % (user[0])
            )
            c.execute(token_query)
            token_record = c.fetchone()

            current_time = int(time.time())
            expire_stamp = current_time + 300

            if isinstance(token_record, tuple) and token_record[3] >= current_time:
                token = token_record[1]
                expire_date = time.ctime(int(token_record[3]))
            else:
                expire_date = time.ctime(int(expire_stamp))
                token = hashlib.md5(
                    f"{username}{password}{expire_date}".encode("utf-8")
                ).hexdigest()

                if isinstance(token_record, tuple):
                    c.execute(
                        "UPDATE tokens SET token = ?, expires = ? WHERE id = ?",
                        (token, expire_stamp, token_record[0]),
                    )
                else:
                    c.execute(
                        "INSERT INTO tokens (token, userid, expires) VALUES (?, ?, ?)",
                        (token, user[0], expire_stamp),
                    )
                conn.commit()

            response["access"]["token"] = {"id": token, "expires": expire_date}
        else:
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
    conn = sqlite3.connect("vAPI.db")
    c = conn.cursor()
    query = "SELECT id, username, password FROM users"
    c.execute(query)
    users = c.fetchall()
    conn.close()
    return {"response": users}


@route("/user/<user_id>", method="GET")
def get_user(user_id):
    token = request.headers.get("X-Auth-Token")
    if not token:
        return (
            json.dumps(
                {"response": {"error": {"message": "X-Auth-Token header missing"}}}
            ),
            401,
        )

    conn = sqlite3.connect("vAPI.db")
    c = conn.cursor()

    try:
        token_query = "SELECT * FROM tokens WHERE token = '%s'" % (str(token))
        c.execute(token_query)
        token_record = c.fetchone()

        response = {}
        if isinstance(token_record, tuple) and token_record[1] == str(token):
            user_query = "SELECT * FROM users WHERE id = '%s'" % (user_id)
            c.execute(user_query)
            user_record = c.fetchone()

            if isinstance(user_record, tuple):
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
    token = request.headers.get("X-Auth-Token")
    if not token:
        return (
            json.dumps(
                {"response": {"error": {"message": "X-Auth-Token header missing"}}}
            ),
            401,
        )

    conn = sqlite3.connect("vAPI.db")
    c = conn.cursor()
    try:
        token_query = "SELECT * FROM tokens WHERE token = '%s'" % (str(token))
        c.execute(token_query)
        token_record = c.fetchone()
        response = {}

        if isinstance(token_record, tuple) and token_record[3] >= int(time.time()):
            data = request.json
            name = data["user"]["username"]
            password = data["user"]["password"]

            if name:
                user_query = "SELECT * FROM users WHERE username = '%s'" % (name)
                c.execute(user_query)
                user_record = c.fetchone()
                if isinstance(user_record, tuple):
                    response["error"] = {"message": "User %s already exists!" % name}
                else:
                    c.execute(
                        "INSERT INTO users (username, password) VALUES (?, ?)",
                        (name, password),
                    )
                    conn.commit()
                    response["user"] = {"username": name, "password": password}
            else:
                response["error"] = {"message": "username cannot be empty!"}
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
    token = request.headers.get("X-Auth-Token")
    if not token:
        return (
            json.dumps(
                {"response": {"error": {"message": "X-Auth-Token header missing"}}}
            ),
            401,
        )

    conn = sqlite3.connect("vAPI.db")
    c = conn.cursor()
    try:
        token_query = "SELECT * FROM tokens WHERE token = '%s'" % (str(token))
        c.execute(token_query)
        token_record = c.fetchone()

        response = {}
        if (
            isinstance(token_record, tuple)
            and token_record[1] == str(token)
            and token_record[3] >= int(time.time())
        ):
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
        conn.close()


@hook("after_request")
def enable_cors():
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Methods"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "*"


init_db()

run(host="0.0.0.0", port=8081, debug=True, reloader=True)
