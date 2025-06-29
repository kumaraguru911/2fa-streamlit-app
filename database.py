import sqlite3
from datetime import datetime

DB_NAME = "users.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    # Create users table
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            totp_secret TEXT NOT NULL,
            failed_attempts INTEGER DEFAULT 0,
            is_locked INTEGER DEFAULT 0
        )
    """)
    # Create audit log table
    c.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            action TEXT,
            timestamp TEXT
        )
    """)
    conn.commit()
    conn.close()

def add_user(username, password_hash, totp_secret):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("""
        INSERT INTO users (username, password_hash, totp_secret) VALUES (?, ?, ?)
    """, (username, password_hash, totp_secret))
    conn.commit()
    conn.close()

def get_user(username):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = c.fetchone()
    conn.close()
    return user

def update_failed_attempts(username, attempts):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("""
        UPDATE users SET failed_attempts = ? WHERE username = ?
    """, (attempts, username))
    conn.commit()
    conn.close()

def lock_user(username):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("""
        UPDATE users SET is_locked = 1 WHERE username = ?
    """, (username,))
    conn.commit()
    conn.close()

def add_audit_log(username, action):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("""
        INSERT INTO audit_log (username, action, timestamp) VALUES (?, ?, ?)
    """, (username, action, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()

def get_all_users():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT username, is_locked, failed_attempts FROM users")
    users = c.fetchall()
    conn.close()
    return users

def get_audit_logs():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT username, action, timestamp FROM audit_log ORDER BY timestamp DESC")
    logs = c.fetchall()
    conn.close()
    return logs

def delete_user(username):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE username = ?", (username,))
    conn.commit()
    conn.close()
def delete_audit_log(log_id):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("DELETE FROM audit_log WHERE id = ?", (log_id,))
    conn.commit()
    conn.close()

def reset_failed_attempts(username):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("""
        UPDATE users SET failed_attempts = 0 WHERE username = ?
    """, (username,))
    conn.commit()
    conn.close()   

def unlock_user(username):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("""
        UPDATE users SET is_locked = 0 WHERE username = ?
    """, (username,))
    conn.commit()
    conn.close()

def get_user_totp_secret(username):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT totp_secret FROM users WHERE username = ?", (username,))
    secret = c.fetchone()
    conn.close()
    return secret[0] if secret else None

def update_totp_secret(username, new_secret):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("""
        UPDATE users SET totp_secret = ? WHERE username = ?
    """, (new_secret, username))
    conn.commit()
    conn.close()

