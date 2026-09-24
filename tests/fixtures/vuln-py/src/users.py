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
