import hashlib
import sqlite3
import time

DATABASE_FILE = "vAPI.db"


def init_db():
    conn = None
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        c = conn.cursor()

        print(f"Checking/creating table 'users' in {DATABASE_FILE}...")
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL
            )
        """
        )
        print("Table 'users' checked/created.")

        print(f"Checking/creating table 'tokens' in {DATABASE_FILE}...")
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT NOT NULL UNIQUE,
                userid INTEGER NOT NULL,
                expires INTEGER NOT NULL,
                FOREIGN KEY (userid) REFERENCES users(id)
            )
        """
        )
        print("Table 'tokens' checked/created.")

        # --- Добавляем или проверяем пользователя admin (id 1) ---
        c.execute("SELECT id FROM users WHERE username = 'admin'")
        admin_user = c.fetchone()
        if admin_user is None:
            c.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                ("admin", "password"),
            )
            conn.commit()
            print("Added default user: admin/password (ID will be 1)")
        else:
            print(f"User 'admin' already exists with ID: {admin_user[0]}.")

        # --- Добавляем или проверяем пользователя с ID 10 ---
        c.execute("SELECT id FROM users WHERE id = 10")
        user_10 = c.fetchone()
        if user_10 is None:
            # Вставляем пользователя с явным ID 10.
            # Это может не сработать, если AUTOINCREMENT уже дошел до 10+.
            # Более надежный способ: временно отключить AUTOINCREMENT, вставить, затем включить.
            # Но для простоты, попробуем так, или создадим нового пользователя
            # и обновим его ID.
            # Для теста, просто создадим нового пользователя, а если нужен именно 10,
            # можно удалить vAPI.db и добавить его первым.
            print("Attempting to add user with ID 10...")
            try:
                c.execute(
                    "INSERT INTO users (id, username, password) VALUES (?, ?, ?)",
                    (10, "admin_super", "superpassword"),
                )
                conn.commit()
                print("Added admin_super/superpassword with ID 10.")
            except sqlite3.IntegrityError:
                print(
                    "Could not add user with ID 10 directly (ID already taken or AUTOINCREMENT conflict)."
                )
                # Если ID 10 уже занят, или AUTOINCREMENT мешает,
                # можно просто создать еще одного пользователя и обновить его ID до 10.
                # Но для простоты демонстрации, если не сработает, то нужно будет
                # удалить vAPI.db и запустить init_db.py первым.

        else:
            print(f"User with ID 10 ({user_10[0]}) already exists.")

        conn.commit()
        print(f"Database {DATABASE_FILE} initialized successfully.")

    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()


if __name__ == "__main__":
    init_db()
