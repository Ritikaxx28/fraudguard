import sqlite3
from datetime import datetime

DB_PATH = "fraudguard.db"

def get_conn():
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            input_text TEXT NOT NULL,
            input_type TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            verdict TEXT NOT NULL,
            explanation TEXT NOT NULL,
            explanation_tamil TEXT,
            scanned_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    conn.commit()
    conn.close()

def register_user(email, password):
    try:
        conn = get_conn()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (email, password, created_at) VALUES (?, ?, ?)",
            (email, password, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        return False
    except Exception as e:
        print(f"Register error: {e}")
        return False

def get_user(email, password):
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT id, email FROM users WHERE email=? AND password=?", (email, password))
    user = cursor.fetchone()
    conn.close()
    return user

def save_scan(user_id, input_text, input_type, risk_score, verdict, explanation, explanation_tamil=""):
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO scan_history
        (user_id, input_text, input_type, risk_score, verdict, explanation, explanation_tamil, scanned_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        user_id, input_text, input_type, risk_score, verdict,
        explanation, explanation_tamil,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))
    conn.commit()
    conn.close()

def get_history(user_id, limit=20):
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, input_text, input_type, risk_score, verdict, scanned_at
        FROM scan_history
        WHERE user_id=?
        ORDER BY scanned_at DESC
        LIMIT ?
    """, (user_id, limit))
    rows = cursor.fetchall()
    conn.close()
    return rows

def get_scan_by_id(scan_id):
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scan_history WHERE id=?", (scan_id,))
    row = cursor.fetchone()
    conn.close()
    return row
