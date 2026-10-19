import app as auth_app
import pytest


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(auth_app, "DB_PATH", tmp_path / "test_auth.db")
    auth_app.ATTEMPTS.clear()
    auth_app.app.config.update(TESTING=True, SECRET_KEY="test-only-secret")
    with auth_app.app.test_client() as client:
        yield client


def register(client, username="student01", password="StrongPassphrase123"):
    return client.post("/register", json={"username": username, "password": password})


def test_password_is_hashed(client):
    assert register(client).status_code == 201
    with auth_app.connect_db() as conn:
        row = conn.execute("SELECT password_hash FROM users WHERE username = ?", ("student01",)).fetchone()
    assert row["password_hash"] != "StrongPassphrase123"
    assert row["password_hash"].startswith("scrypt:")


def test_validation(client):
    assert client.post("/register", json={"username": "bad name", "password": "StrongPassphrase123"}).status_code == 400
    assert client.post("/register", json={"username": "student01", "password": "short"}).status_code == 400


def test_login_protected_route_and_logout(client):
    assert register(client).status_code == 201
    assert client.get("/me").status_code == 401
    assert client.post("/login", json={"username": "student01", "password": "StrongPassphrase123"}).status_code == 200
    assert client.get("/me").status_code == 200
    assert client.post("/logout").status_code == 200
    assert client.get("/me").status_code == 401


def test_generic_auth_error(client):
    unknown = client.post("/login", json={"username": "missing", "password": "WrongPassphrase123"})
    register(client)
    wrong = client.post("/login", json={"username": "student01", "password": "WrongPassphrase123"})
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.get_json() == wrong.get_json()


def test_rate_limit(client):
    for _ in range(auth_app.MAX_ATTEMPTS):
        assert client.post("/login", json={"username": "missing", "password": "WrongPassphrase123"}).status_code == 401
    assert client.post("/login", json={"username": "missing", "password": "WrongPassphrase123"}).status_code == 429
