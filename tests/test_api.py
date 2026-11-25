import sqlite3

import jwt
import pytest
from werkzeug.security import generate_password_hash

from app import AUDIENCE, ISSUER, create_app


@pytest.fixture
def app(tmp_path):
    application = create_app(
        {
            "TESTING": True,
            "DATABASE": str(tmp_path / "test.sqlite3"),
            "JWT_SECRET": "test-secret-with-at-least-32-bytes-123456",
        }
    )
    with sqlite3.connect(application.config["DATABASE"]) as db:
        db.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            ("student", generate_password_hash("correct-password-123", method="scrypt")),
        )
        db.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            ("other", generate_password_hash("another-password-123", method="scrypt")),
        )
    return application


@pytest.fixture
def client(app):
    return app.test_client()


def login(client, username="student", password="correct-password-123"):
    return client.post("/auth/login", json={"username": username, "password": password})


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def test_registration_and_login(client, app):
    credentials = {"username": "new_user", "password": "long-password-123"}
    response = client.post("/auth/register", json=credentials)
    assert response.status_code == 201
    assert "password" not in response.json
    with sqlite3.connect(app.config["DATABASE"]) as db:
        password_hash = db.execute(
            "SELECT password_hash FROM users WHERE username = ?", (credentials["username"],)
        ).fetchone()[0]
    assert password_hash.startswith("scrypt:")
    assert credentials["password"] not in password_hash
    assert login(client, **credentials).status_code == 200
    assert client.post("/auth/register", json=credentials).status_code == 409


def test_registration_rejects_invalid_input(client):
    for payload in (None, {}, {"username": "' OR 1=1 --", "password": "long-password-123"},
                    {"username": "new_user", "password": "short"},
                    {"username": "new_user", "password": "x" * 1025}):
        assert client.post("/auth/register", json=payload).status_code == 400


def test_login_and_protected_access(client):
    assert client.get("/api/data").status_code == 401
    response = login(client)
    assert response.status_code == 200
    token = response.json["access_token"]
    assert response.json["expires_in"] == 1800
    assert client.get("/api/data", headers=bearer(token)).json == {"items": []}


def test_wrong_password_and_sql_injection_are_rejected(client):
    assert login(client, password="wrong-password").status_code == 401
    assert login(client, username="' OR 1=1 --").status_code == 401
    assert client.post("/auth/login", json={"username": 1, "password": "x"}).status_code == 400


def test_content_is_escaped_and_private(client):
    token = login(client).json["access_token"]
    content = "<script>alert('x')</script>"
    response = client.post("/api/data", json={"content": content}, headers=bearer(token))
    assert response.status_code == 201
    assert response.json["content"] == "&lt;script&gt;alert(&#x27;x&#x27;)&lt;/script&gt;"
    assert client.get("/api/data", headers=bearer(token)).json["items"][0]["content"] == response.json["content"]
    other_token = login(client, "other", "another-password-123").json["access_token"]
    assert client.get("/api/data", headers=bearer(other_token)).json == {"items": []}


def test_invalid_and_expired_tokens_are_rejected(client, app):
    token = login(client).json["access_token"]
    assert client.get("/api/data", headers=bearer(token + "x")).status_code == 401
    expired = jwt.encode(
        {"sub": "1", "iss": ISSUER, "aud": AUDIENCE, "iat": 1, "exp": 2},
        app.config["JWT_SECRET"],
        algorithm="HS256",
    )
    assert client.get("/api/data", headers=bearer(expired)).status_code == 401


def test_create_user_cli(app):
    runner = app.test_cli_runner()
    result = runner.invoke(args=["create-user", "new_user"], input="long-password-123\nlong-password-123\n")
    assert result.exit_code == 0
    with sqlite3.connect(app.config["DATABASE"]) as db:
        password_hash = db.execute(
            "SELECT password_hash FROM users WHERE username = ?", ("new_user",)
        ).fetchone()[0]
    assert password_hash.startswith("scrypt:")
    assert "long-password-123" not in password_hash
