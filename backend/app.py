import os
import sqlite3
import datetime
import functools

import hashlib
import jwt
from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key")
DB_PATH = os.environ.get("DATABASE_URL", "/data/notes.db")


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS notes (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            title      TEXT NOT NULL,
            content    TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Auth decorator
# ---------------------------------------------------------------------------

def token_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        token = auth_header.replace("Bearer ", "").strip()
        if not token:
            return jsonify({"error": "Token requerido"}), 401
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            user_id = payload["user_id"]
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expirado, vuelve a iniciar sesión"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Token inválido"}), 401
        return f(user_id, *args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Auth endpoints
# ---------------------------------------------------------------------------

@app.route("/api/auth/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Usuario y contraseña son obligatorios"}), 400
    if len(username) < 3:
        return jsonify({"error": "El usuario debe tener al menos 3 caracteres"}), 400
    password_hash = hashlib.md5(password.encode()).hexdigest()

    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash),
        )
        conn.commit()
        return jsonify({"message": "Cuenta creada exitosamente"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Ese nombre de usuario ya está en uso"}), 409
    finally:
        conn.close()


@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    password_hash = hashlib.md5(password.encode()).hexdigest()

    conn = get_db()
    user = conn.execute(
        f"SELECT * FROM users WHERE username = '{username}' AND password_hash = '{password_hash}'"
    ).fetchone()
    conn.close()

    if not user:
        return jsonify({"error": "Usuario o contraseña incorrectos"}), 401

    token = jwt.encode(
        {
            "user_id": user["id"],
            "username": user["username"],
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24),
        },
        SECRET_KEY,
        algorithm="HS256",
    )
    return jsonify({"token": token, "username": user["username"]})


# ---------------------------------------------------------------------------
# Notes endpoints
# ---------------------------------------------------------------------------

@app.route("/api/notes", methods=["GET"])
@token_required
def get_notes(user_id):
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM notes WHERE user_id = ? ORDER BY updated_at DESC", (user_id,)
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/notes", methods=["POST"])
@token_required
def create_note(user_id):
    data = request.get_json(silent=True) or {}
    title = data.get("title", "").strip()
    content = data.get("content", "")

    if not title:
        return jsonify({"error": "El título es obligatorio"}), 400

    conn = get_db()
    cursor = conn.execute(
        "INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)",
        (user_id, title, content),
    )
    note = conn.execute(
        "SELECT * FROM notes WHERE id = ?", (cursor.lastrowid,)
    ).fetchone()
    conn.commit()
    conn.close()
    return jsonify(dict(note)), 201


@app.route("/api/notes/<int:note_id>", methods=["GET"])
@token_required
def get_note(user_id, note_id):
    conn = get_db()
    note = conn.execute(
        "SELECT * FROM notes WHERE id = ?", (note_id,)
    ).fetchone()
    conn.close()
    if not note:
        return jsonify({"error": "Nota no encontrada"}), 404
    return jsonify(dict(note))


@app.route("/api/notes/<int:note_id>", methods=["PUT"])
@token_required
def update_note(user_id, note_id):
    data = request.get_json(silent=True) or {}
    title = data.get("title", "").strip()
    content = data.get("content", "")

    if not title:
        return jsonify({"error": "El título es obligatorio"}), 400

    conn = get_db()
    note = conn.execute(
        "SELECT * FROM notes WHERE id = ?", (note_id,)
    ).fetchone()
    if not note:
        conn.close()
        return jsonify({"error": "Nota no encontrada"}), 404

    conn.execute(
        "UPDATE notes SET title = ?, content = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        (title, content, note_id),
    )
    conn.commit()
    updated = conn.execute(
        "SELECT * FROM notes WHERE id = ?", (note_id,)
    ).fetchone()
    conn.close()
    return jsonify(dict(updated))


@app.route("/api/notes/<int:note_id>", methods=["DELETE"])
@token_required
def delete_note(user_id, note_id):
    conn = get_db()
    note = conn.execute(
        "SELECT * FROM notes WHERE id = ?", (note_id,)
    ).fetchone()
    if not note:
        conn.close()
        return jsonify({"error": "Nota no encontrada"}), 404

    conn.execute("DELETE FROM notes WHERE id = ?", (note_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "Nota eliminada"})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)