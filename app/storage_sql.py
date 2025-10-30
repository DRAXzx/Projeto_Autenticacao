import sqlite3
from typing import Optional
from dataclasses import dataclass
import os


DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "database", "auth.db")


@dataclass
class User:
    id: int
    name: str
    email: str
    document: str
    password: str


def create_connection():
   
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            document TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def add_user(name: str, email: str, document: str, password: str) -> User:
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO usuarios (name, email, document, password) VALUES (?, ?, ?, ?)",
        (name, email, document, password)
    )
    conn.commit()
    user_id = cursor.lastrowid
    conn.close()
    return User(id=user_id, name=name, email=email, document=document, password=password)


def find_user_by_email(email: str) -> Optional[User]:
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM usuarios WHERE email = ?", (email,))
    row = cursor.fetchone()
    conn.close()
    return User(**row) if row else None


def find_user_by_document(document: str) -> Optional[User]:
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM usuarios WHERE document = ?", (document,))
    row = cursor.fetchone()
    conn.close()
    return User(**row) if row else None


def find_user_by_email_and_document(email: str, document: str) -> Optional[User]:
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM usuarios WHERE email = ? AND document = ?", (email, document))
    row = cursor.fetchone()
    conn.close()
    return User(**row) if row else None


def update_password(email: str, document: str, new_password: str):
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE usuarios SET password = ? WHERE email = ? AND document = ?",
        (new_password, email, document)
    )
    conn.commit()
    conn.close()
