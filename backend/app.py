import os
import sqlite3
import datetime
import functools
import logging

import bcrypt
import jwt
import pyotp
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
CORS(app, origins=["https://localhost"]) # Solo permitir accesos locales (HTTPS)

limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
# Hay varios niveles de log: DEBUG, INFO, WARNING, ERROR, CRITICAL
# Al poner INFO, se registra todo menos los DEBUG
# Format define la estructura que seguirán todos los logs

security_log = logging.getLogger("security")
# Crea un canal de logs especifico para seguridad, para facilitar el analisis

SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY no está definida. Define la variable de entorno antes de arrancar.")
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
            totp_secret   TEXT NOT NULL,
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
    honeypot_hash = bcrypt.hashpw(b"PaquitoElChocolatero", bcrypt.gensalt()).decode()
    honeypot_totp = pyotp.random_base32()  # Nunca se usará: el honeypot se activa antes del paso TOTP
    conn.execute(
        "INSERT OR IGNORE INTO users (username, password_hash, totp_secret) VALUES (?, ?, ?)",
        ("Paco", honeypot_hash, honeypot_totp),
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Auth decorator
# ---------------------------------------------------------------------------

def token_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get("token")  # Lee la cookie
        if not token:
            return jsonify({"error": "Token requerido"}), 401
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            if payload.get("mfa_pending"):
                return jsonify({"error": "Autenticación incompleta: falta el código TOTP"}), 401
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
@limiter.limit("3 per minute;10 per day") 
    # 3 intentos por minuto
    # 10 al dia por IP
    # Es muy raro que un usuario supere estos limites para crear una cuenta
def register():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Usuario y contraseña son obligatorios"}), 400
    if len(username) < 3:
        return jsonify({"error": "El usuario debe tener al menos 3 caracteres"}), 400
    if len(password) < 8:
        return jsonify({"error": "La contraseña debe tener al menos 8 caracteres"}), 400
    if len(password) > 72: # El Hash consume recursos
        return jsonify({"error": "La contraseña no puede superar los 72 caracteres"}), 400
    if not any(c.isupper() for c in password):
        return jsonify({"error": "La contraseña debe contener al menos una mayúscula"}), 400
    if not any(c.isdigit() for c in password):
        return jsonify({"error": "La contraseña debe contener al menos un número"}), 400

    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    totp_secret = pyotp.random_base32()
    # provisioning_uri genera la URL otpauth:// estándar que entienden todas las apps de autenticación
    totp_uri = pyotp.TOTP(totp_secret).provisioning_uri(name=username, issuer_name="NotasFacil")

    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, totp_secret) VALUES (?, ?, ?)",
            (username, password_hash, totp_secret),
        )
        conn.commit()
        # Devolvemos el URI para que el frontend lo muestre al usuario
        return jsonify({"totp_uri": totp_uri, "totp_secret": totp_secret}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Ese nombre de usuario ya está en uso"}), 409
    finally:
        conn.close()


@app.route("/api/auth/login", methods=["POST"])
@limiter.limit("5 per minute;20 per day")
    # 5 intentos por minuto
    # 20 al dia por IP
    # Al tener JWT, es muy raro que un usuario legitimo supere el limite
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    # Obtener IP del cliente

    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()

    if not user or not bcrypt.checkpw(
        password.encode(), user["password_hash"].encode()
    ):
        # Loging fallido
        security_log.warning("Login fallido - usuario: %s IP: %s", username, ip)
        return jsonify({"error": "Usuario y/o contraseña incorrectos"}), 401

    # HONEYPOT: El usuario "admin" no hace nada
        # Al detectar que alguien accede con el usuario sabemos:
        # 1. Puede estar probando contraseñas comunes --> acceso malicioso
        # 2. 
    if username == "Paco":
        security_log.critical("HONEYPOT ACTIVADO - IP: %s", ip)
        return jsonify({"error": "Usuario o contraseña incorrectos"}), 401

    # Contraseña correcta: emitir token temporal de MFA pendiente (5 minutos)
    # Este token NO da acceso a las notas; solo sirve para el segundo paso (TOTP).
    security_log.info("Contraseña correcta, esperando TOTP - usuario: %s IP: %s", username, ip)
    mfa_token = jwt.encode(
        {
            "user_id": user["id"],
            "mfa_pending": True,
            "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5),
        },
        SECRET_KEY,
        algorithm="HS256",
    )
    response = jsonify({"mfa_required": True})
    response.set_cookie(
        "mfa_token",
        mfa_token,
        httponly=True,
        secure=True,
        samesite="Strict",
        max_age=300,  # 5 minutos
        path="/api/auth/totp/verify",  # Solo se envía a este endpoint
    )
    return response

@app.route("/api/auth/totp/verify", methods=["POST"])
@limiter.limit("5 per minute")  # Limitar intentos de TOTP para evitar fuerza bruta
def totp_verify():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    mfa_token = request.cookies.get("mfa_token")
    if not mfa_token:
        return jsonify({"error": "Token MFA requerido"}), 401

    try:
        payload = jwt.decode(mfa_token, SECRET_KEY, algorithms=["HS256"])
        if not payload.get("mfa_pending"):
            return jsonify({"error": "Token inválido"}), 401
        user_id = payload["user_id"]
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "El código TOTP ha expirado, vuelve a iniciar sesión"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Token inválido"}), 401

    data = request.get_json(silent=True) or {}
    code = data.get("code", "").strip()

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()

    if not user or not pyotp.TOTP(user["totp_secret"]).verify(code, valid_window=1):
        security_log.warning("TOTP fallido - user_id: %s IP: %s", user_id, ip)
        return jsonify({"error": "Código TOTP incorrecto"}), 401

    # TOTP correcto: emitir cookie de sesión real y borrar el token temporal
    security_log.info("Login completo (TOTP ok) - usuario: %s IP: %s", user["username"], ip)
    token = jwt.encode(
        {
            "user_id": user["id"],
            "username": user["username"],
            "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=24),
        },
        SECRET_KEY,
        algorithm="HS256",
    )
    response = jsonify({"username": user["username"]})
    response.set_cookie(
        "token", token,
        httponly=True, secure=True, samesite="Strict",
        max_age=86400, path="/",
    )
    response.delete_cookie("mfa_token", path="/api/auth/totp/verify", samesite="Strict")
    return response


@app.route("/api/auth/logout", methods=["POST"])
@token_required
def logout(user_id):
    security_log.info("Logout - user_id: %s", user_id)
    response = jsonify({"message": "Sesión cerrada"})
    response.delete_cookie("token", path="/", samesite="Strict")
    return response


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
    # Validaciones para evitar abusos y posible DoS, no es razonable permitir notas tan grandes
    if len(title) > 200:
        return jsonify({"error": "El título no puede superar los 200 caracteres"}), 400
    if len(content) > 50_000:
        return jsonify({"error": "El contenido no puede superar los 50000 caracteres"}), 400

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


@app.route("/api/notes/<int:note_id>", methods=["PUT"])
@token_required
def update_note(user_id, note_id):
    data = request.get_json(silent=True) or {}
    title = data.get("title", "").strip()
    content = data.get("content", "")

    if not title:
        return jsonify({"error": "El título es obligatorio"}), 400
    if len(title) > 200:
        return jsonify({"error": "El título no puede superar los 200 caracteres"}), 400
    if len(content) > 50_000:
        return jsonify({"error": "El contenido no puede superar los 50000 caracteres"}), 400

    conn = get_db()
    note = conn.execute(
        "SELECT * FROM notes WHERE id = ? AND user_id = ?", (note_id, user_id)
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
        "SELECT * FROM notes WHERE id = ? AND user_id = ?", (note_id, user_id)
    ).fetchone()
    if not note:
        conn.close()
        return jsonify({"error": "Nota no encontrada"}), 404

    conn.execute("DELETE FROM notes WHERE id = ?", (note_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "Nota eliminada"})


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

@app.errorhandler(Exception)
def handle_exception(e):
    # Registra el error completo internamente para poder depurarlo
    app.logger.error("Unhandled exception: %s", e, exc_info=True)
    # Pero el cliente solo recibe un mensaje generico, sin detalles internos
    return jsonify({"error": "Error interno del servidor"}), 500

@app.errorhandler(404)
def handle_404(_):
    return jsonify({"error": "Recurso no encontrado"}), 404

@app.errorhandler(405)
def handle_405(_):
    return jsonify({"error": "Método no permitido"}), 405


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)