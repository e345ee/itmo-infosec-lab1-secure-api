import os
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
from html import escape
from pathlib import Path

import click
import jwt
from flask import Flask, current_app, g, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash


ISSUER = "secure-lab-api"
AUDIENCE = "secure-lab-api-users"
BEARER_SCHEME = "Bearer"
TOKEN_LIFETIME = timedelta(minutes=30)
USERNAME_PATTERN = re.compile(r"[A-Za-z0-9_]{3,32}\Z")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def require_auth(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        authorization = request.headers.get("Authorization", "")
        scheme, separator, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not separator or not token or " " in token:
            return jsonify(error="Требуется действительный Bearer-токен"), 401
        try:
            claims = jwt.decode(
                token,
                current_app.config["JWT_SECRET"],
                algorithms=["HS256"],
                audience=AUDIENCE,
                issuer=ISSUER,
                options={"require": ["exp", "iat", "sub", "aud", "iss"]},
            )
            user_id = int(claims["sub"])
        except (jwt.InvalidTokenError, ValueError, TypeError):
            return jsonify(error="Требуется действительный Bearer-токен"), 401
        user = get_db().execute("SELECT id FROM users WHERE id = ?", (user_id,)).fetchone()
        if user is None:
            return jsonify(error="Требуется действительный Bearer-токен"), 401
        g.user_id = user_id
        return view(*args, **kwargs)

    return wrapped


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.update(
        DATABASE=os.environ.get("DATABASE_PATH", str(Path(app.instance_path) / "data.sqlite3")),
        JWT_SECRET=os.environ.get("JWT_SECRET_KEY"),
        MAX_CONTENT_LENGTH=16 * 1024,
    )
    if test_config:
        app.config.update(test_config)
    secret = app.config["JWT_SECRET"]
    if not isinstance(secret, str) or len(secret.encode("utf-8")) < 32:
        raise RuntimeError("JWT_SECRET_KEY должен содержать не менее 32 байт")
    database_path = Path(app.config["DATABASE"])
    database_path.parent.mkdir(parents=True, exist_ok=True)

    @app.teardown_appcontext
    def close_db(error):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    @app.after_request
    def secure_response(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.errorhandler(413)
    def request_too_large(error):
        return jsonify(error="Слишком большой запрос"), 413

    @app.post("/auth/register")
    def register():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify(error="Ожидается JSON-объект"), 400
        username = payload.get("username")
        password = payload.get("password")
        if not isinstance(username, str) or USERNAME_PATTERN.fullmatch(username) is None:
            return jsonify(error="Логин: 3–32 символа A–Z, a–z, 0–9 или _"), 400
        if not isinstance(password, str) or not 12 <= len(password) <= 1024:
            return jsonify(error="Пароль должен содержать от 12 до 1024 символов"), 400
        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, generate_password_hash(password, method="scrypt")),
            )
            db.commit()
        except sqlite3.IntegrityError:
            return jsonify(error="Пользователь уже существует"), 409
        return jsonify(message="Пользователь создан"), 201

    @app.post("/auth/login")
    def login():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify(error="Ожидается JSON-объект"), 400
        username = payload.get("username")
        password = payload.get("password")
        if not isinstance(username, str) or not isinstance(password, str):
            return jsonify(error="Нужны username и password"), 400
        user = get_db().execute(
            "SELECT id, password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()
        if user is None or not check_password_hash(user["password_hash"], password):
            return jsonify(error="Неверный логин или пароль"), 401
        now = datetime.now(timezone.utc)
        token = jwt.encode(
            {
                "sub": str(user["id"]),
                "iss": ISSUER,
                "aud": AUDIENCE,
                "iat": now,
                "exp": now + TOKEN_LIFETIME,
            },
            secret,
            algorithm="HS256",
        )
        return jsonify({"access_token": token, "token_type": BEARER_SCHEME, "expires_in": 1800})

    @app.get("/api/data")
    @require_auth
    def list_data():
        rows = get_db().execute(
            "SELECT id, content FROM entries WHERE owner_id = ? ORDER BY id", (g.user_id,)
        ).fetchall()
        return jsonify(items=[{"id": row["id"], "content": escape(row["content"])} for row in rows])

    @app.post("/api/data")
    @require_auth
    def add_data():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict) or not isinstance(payload.get("content"), str):
            return jsonify(error="Нужно строковое поле content"), 400
        content = payload["content"].strip()
        if not content or len(content) > 500:
            return jsonify(error="Длина content должна быть от 1 до 500 символов"), 400
        db = get_db()
        cursor = db.execute(
            "INSERT INTO entries (owner_id, content) VALUES (?, ?)", (g.user_id, content)
        )
        db.commit()
        return jsonify(id=cursor.lastrowid, content=escape(content)), 201

    @app.cli.command("create-user")
    @click.argument("username")
    def create_user(username):
        if USERNAME_PATTERN.fullmatch(username) is None:
            raise click.ClickException("Логин: 3–32 символа A–Z, a–z, 0–9 или _")
        password = click.prompt("Пароль", hide_input=True, confirmation_prompt=True)
        if len(password) < 12:
            raise click.ClickException("Пароль должен содержать минимум 12 символов")
        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, generate_password_hash(password, method="scrypt")),
            )
            db.commit()
        except sqlite3.IntegrityError as error:
            raise click.ClickException("Пользователь уже существует") from error
        click.echo("Пользователь создан")

    with app.app_context():
        db = get_db()
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS entries (
                id INTEGER PRIMARY KEY,
                owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                content TEXT NOT NULL
            );
            """
        )
        db.commit()

    return app
