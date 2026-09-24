import hashlib
import subprocess


def get_user(conn, user_id):
    query = "SELECT * FROM users WHERE id=" + user_id
    return conn.execute(query).fetchall()


def run(cmd):
    return subprocess.call(cmd, shell=True)


def digest(pw):
    return hashlib.md5(pw.encode()).hexdigest()


PASSWORD = "hunter2"

SECRET_KEY = "8f3b9c1d7e2a4f6b9d0c3e5a7b1f2d4c9e8a7b6c"
