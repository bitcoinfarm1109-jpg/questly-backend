import os
import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import time

from datetime import datetime, timezone, timedelta
from http.cookies import SimpleCookie
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError


# ============================================================
# CONFIGURACIÓN
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
DB_FILE = BASE_DIR / "rbxquestly.db"

HOST = "127.0.0.1"
PORT = 8000

SESSION_HOURS = 8
PBKDF2_ITERATIONS = 600_000
MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCK_MINUTES = 15

# Activar True únicamente cuando el sitio use HTTPS real.
ADMIN_COOKIE_SECURE = False

MIN_REDEEM = 50
MAX_REDEEM = 500

SURVEYS = [
    {"id": "survey1", "title": "Encuesta de videojuegos", "reward": 15},
    {"id": "survey2", "title": "Encuesta de tecnología", "reward": 20},
    {"id": "survey3", "title": "Encuesta de entretenimiento", "reward": 25},
    {"id": "survey4", "title": "Encuesta de compras", "reward": 30},
    {"id": "survey5", "title": "Encuesta de comunidad", "reward": 35},
    {"id": "survey6", "title": "Encuesta especial", "reward": 50},
]

DEFAULT_CONFIG = {
    "theme_mode": "auto",
    "manual_theme": "original",
    "festival_schedule": {
        "halloween": ["10-25", "11-02"],
        "christmas": ["12-01", "12-26"],
        "valentines": ["02-01", "02-15"],
        "easter": ["03-20", "04-25"],
        "independence": ["07-01", "07-05"],
    },
    "hero_title": "Gana recompensas jugando",
    "hero_highlight": "a tu manera",
    "hero_subtitle": "Completa actividades y acumula puntos para canjear Robux.",
    "announcement": "",
}


# ============================================================
# BASE DE DATOS Y MIGRACIONES
# ============================================================

def connect_db():
    db = sqlite3.connect(DB_FILE, timeout=20)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    db.execute("PRAGMA busy_timeout = 20000")
    return db


def now():
    return datetime.now(timezone.utc).isoformat()


def add_column_if_missing(db, table, column, definition):
    columns = {
        row["name"]
        for row in db.execute(f"PRAGMA table_info({table})").fetchall()
    }
    if column not in columns:
        db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def initialize_database():
    with connect_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                username TEXT,
                display_name TEXT,
                avatar_url TEXT,
                balance INTEGER DEFAULT 0,
                earned INTEGER DEFAULT 0,
                completed INTEGER DEFAULT 0,
                created_at TEXT
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS completions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                survey_id TEXT NOT NULL,
                reward INTEGER NOT NULL,
                completed_at TEXT,
                UNIQUE(user_id, survey_id)
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                description TEXT,
                amount INTEGER,
                entry_type TEXT,
                created_at TEXT
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                username TEXT,
                amount INTEGER,
                points INTEGER,
                status TEXT DEFAULT 'pending',
                created_at TEXT
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                setting_key TEXT PRIMARY KEY,
                setting_value TEXT
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                created_at TEXT
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS admin_sessions (
                token_hash TEXT PRIMARY KEY,
                csrf_token TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS finance_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entry_type TEXT NOT NULL,
                amount REAL NOT NULL,
                note TEXT,
                created_at TEXT
            )
        """)

        # Seguridad adicional
        db.execute("""
            CREATE TABLE IF NOT EXISTS login_attempts (
                ip_hash TEXT PRIMARY KEY,
                attempts INTEGER NOT NULL DEFAULT 0,
                locked_until TEXT,
                updated_at TEXT NOT NULL
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS user_bans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                duration TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT,
                active INTEGER NOT NULL DEFAULT 1,
                revoked_at TEXT,
                created_by INTEGER
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                details TEXT,
                created_at TEXT NOT NULL
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS admin_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                admin_id INTEGER,
                action TEXT NOT NULL,
                target TEXT,
                details TEXT,
                created_at TEXT NOT NULL
            )
        """)

        # Compatibilidad con sesiones creadas por la versión anterior.
        add_column_if_missing(
            db, "admin_sessions", "admin_id", "INTEGER"
        )

        db.execute("""
            INSERT OR IGNORE INTO settings
            (setting_key, setting_value)
            VALUES ('points_rate', '1')
        """)

        for key, value in DEFAULT_CONFIG.items():
            db.execute("""
                INSERT OR IGNORE INTO settings
                (setting_key, setting_value)
                VALUES (?, ?)
            """, (key, json.dumps(value)))


def get_setting(key, default=None):
    with connect_db() as db:
        row = db.execute(
            "SELECT setting_value FROM settings WHERE setting_key=?",
            (key,)
        ).fetchone()

    if not row:
        return default

    try:
        return json.loads(row["setting_value"])
    except (ValueError, TypeError):
        return row["setting_value"]


def save_setting(key, value):
    with connect_db() as db:
        db.execute("""
            INSERT INTO settings (setting_key, setting_value)
            VALUES (?, ?)
            ON CONFLICT(setting_key)
            DO UPDATE SET setting_value=excluded.setting_value
        """, (key, json.dumps(value)))


def get_config():
    config = dict(DEFAULT_CONFIG)
    for key in DEFAULT_CONFIG:
        config[key] = get_setting(key, DEFAULT_CONFIG[key])
    return config


def get_points_rate():
    try:
        return float(get_setting("points_rate", 1))
    except (ValueError, TypeError):
        return 1.0


def add_history(db, user_id, description, amount, entry_type):
    db.execute("""
        INSERT INTO history
        (user_id, description, amount, entry_type, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (user_id, description, amount, entry_type, now()))


def audit(db, admin_id, action, target="", details=""):
    db.execute("""
        INSERT INTO admin_audit
        (admin_id, action, target, details, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (admin_id, action, str(target)[:150], str(details)[:1000], now()))


def security_event(db, user_id, event_type, severity, details=""):
    db.execute("""
        INSERT INTO security_events
        (user_id, event_type, severity, details, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (
        str(user_id) if user_id else None,
        event_type[:80],
        severity[:20],
        str(details)[:1000],
        now()
    ))


def active_ban(user_id):
    with connect_db() as db:
        ban = db.execute("""
            SELECT * FROM user_bans
            WHERE user_id=? AND active=1
            ORDER BY id DESC LIMIT 1
        """, (str(user_id),)).fetchone()

        if not ban:
            return None

        if ban["expires_at"]:
            try:
                if datetime.fromisoformat(ban["expires_at"]) <= datetime.now(timezone.utc):
                    db.execute(
                        "UPDATE user_bans SET active=0 WHERE id=?",
                        (ban["id"],)
                    )
                    return None
            except ValueError:
                return dict(ban)

        return dict(ban)


def get_user_state(user_id):
    with connect_db() as db:
        user = db.execute(
            "SELECT * FROM users WHERE user_id=?",
            (str(user_id),)
        ).fetchone()

        if not user:
            return None

        completions = db.execute("""
            SELECT survey_id, reward, completed_at
            FROM completions WHERE user_id=?
            ORDER BY id DESC
        """, (str(user_id),)).fetchall()

        history = db.execute("""
            SELECT description, amount, entry_type, created_at
            FROM history WHERE user_id=?
            ORDER BY id DESC LIMIT 50
        """, (str(user_id),)).fetchall()

        requests = db.execute("""
            SELECT id, amount, points, status, created_at
            FROM requests WHERE user_id=?
            ORDER BY id DESC
        """, (str(user_id),)).fetchall()

    result = dict(user)
    result["completions"] = [dict(x) for x in completions]
    result["history"] = [dict(x) for x in history]
    result["requests"] = [dict(x) for x in requests]
    result["pointsRate"] = get_points_rate()
    result["minRedeem"] = MIN_REDEEM
    result["maxRedeem"] = MAX_REDEEM
    return result


# ============================================================
# CONTRASEÑAS Y SESIONES
# ============================================================

def hash_password(password, salt):
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt),
        PBKDF2_ITERATIONS
    ).hex()


def create_admin_session(db, admin_id):
    token = secrets.token_urlsafe(48)
    csrf = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    expires = (
        datetime.now(timezone.utc)
        + timedelta(hours=SESSION_HOURS)
    ).isoformat()

    db.execute("""
        INSERT INTO admin_sessions
        (token_hash, csrf_token, expires_at, created_at, admin_id)
        VALUES (?, ?, ?, ?, ?)
    """, (token_hash, csrf, expires, now(), admin_id))

    return token, csrf


# ============================================================
# SERVIDOR
# ============================================================

class RbxQuestlyHandler(SimpleHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(BASE_DIR), **kwargs)

    def log_message(self, format, *args):
        # Evita llenar la consola con datos de cada solicitud.
        print("[RbxQuestly]", format % args)

    def send_json(self, data, status=200, extra_headers=None):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")

        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("X-Frame-Options", "DENY")

        cookie = getattr(self, "_pending_admin_cookie", None)
        headers = dict(extra_headers or {})

        if cookie:
            headers["Set-Cookie"] = cookie
            self._pending_admin_cookie = None

        for key, value in headers.items():
            self.send_header(key, value)

        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 100_000:
                return None
            raw = self.rfile.read(length)
            data = json.loads(raw.decode("utf-8"))
            return data if isinstance(data, dict) else None
        except (ValueError, UnicodeDecodeError):
            return None

    def client_ip(self):
        # No confiar en X-Forwarded-For.
        return self.client_address[0]

    def local_request(self):
        return self.client_ip() in ("127.0.0.1", "::1")

    def get_admin_token(self):
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
            morsel = cookie.get("rq_admin")
            return morsel.value if morsel else None
        except Exception:
            return None

    def check_origin(self):
        origin = self.headers.get("Origin")
        if not origin:
            return True

        try:
            return urlparse(origin).netloc == self.headers.get("Host")
        except Exception:
            return False

    def admin_session(self, require_csrf=False):
        token = self.get_admin_token()
        if not token or len(token) > 200:
            return None

        token_hash = hashlib.sha256(token.encode()).hexdigest()

        with connect_db() as db:
            session = db.execute("""
                SELECT * FROM admin_sessions WHERE token_hash=?
            """, (token_hash,)).fetchone()

            if not session:
                return None

            try:
                expires = datetime.fromisoformat(session["expires_at"])
                if expires <= datetime.now(timezone.utc):
                    db.execute(
                        "DELETE FROM admin_sessions WHERE token_hash=?",
                        (token_hash,)
                    )
                    return None
            except (ValueError, TypeError):
                return None

            # Las sesiones antiguas sin admin_id se invalidan.
            if not session["admin_id"]:
                db.execute(
                    "DELETE FROM admin_sessions WHERE token_hash=?",
                    (token_hash,)
                )
                return None

            if require_csrf:
                if not self.check_origin():
                    return None

                supplied = self.headers.get("X-CSRF-Token", "")
                if not hmac.compare_digest(
                    supplied, session["csrf_token"]
                ):
                    return None

            return dict(session)

    def require_admin(self, require_csrf=False):
        session = self.admin_session(require_csrf)
        if not session:
            self.send_json(
                {"error": "Acceso administrativo no autorizado."},
                401
            )
            return None
        return session

    def admin_cookie(self, token):
        secure = "; Secure" if ADMIN_COOKIE_SECURE else ""
        self._pending_admin_cookie = (
            f"rq_admin={token}; HttpOnly; SameSite=Strict; "
            f"Path=/; Max-Age={SESSION_HOURS * 3600}{secure}"
        )

    def clear_admin_cookie(self):
        secure = "; Secure" if ADMIN_COOKIE_SECURE else ""
        return {
            "Set-Cookie": (
                "rq_admin=; HttpOnly; SameSite=Strict; "
                f"Path=/; Max-Age=0{secure}"
            )
        }

    def login_ip_hash(self):
        return hashlib.sha256(
            self.client_ip().encode()
        ).hexdigest()

    def login_locked(self, db):
        ip_hash = self.login_ip_hash()
        row = db.execute(
            "SELECT * FROM login_attempts WHERE ip_hash=?",
            (ip_hash,)
        ).fetchone()

        if not row or not row["locked_until"]:
            return False

        try:
            return datetime.fromisoformat(row["locked_until"]) > datetime.now(timezone.utc)
        except ValueError:
            return False

    def record_login_failure(self, db):
        ip_hash = self.login_ip_hash()
        row = db.execute(
            "SELECT attempts FROM login_attempts WHERE ip_hash=?",
            (ip_hash,)
        ).fetchone()

        attempts = (row["attempts"] if row else 0) + 1
        locked_until = None

        if attempts >= MAX_LOGIN_ATTEMPTS:
            locked_until = (
                datetime.now(timezone.utc)
                + timedelta(minutes=LOGIN_LOCK_MINUTES)
            ).isoformat()
            attempts = 0

        db.execute("""
            INSERT INTO login_attempts
            (ip_hash, attempts, locked_until, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(ip_hash) DO UPDATE SET
                attempts=excluded.attempts,
                locked_until=excluded.locked_until,
                updated_at=excluded.updated_at
        """, (ip_hash, attempts, locked_until, now()))

    def clear_login_failures(self, db):
        db.execute(
            "DELETE FROM login_attempts WHERE ip_hash=?",
            (self.login_ip_hash(),)
        )

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        if path == "/api/public/config":
            self.send_json({
                "config": get_config(),
                "surveys": SURVEYS,
                "minRedeem": MIN_REDEEM,
                "maxRedeem": MAX_REDEEM
            })
            return

        if path == "/api/state":
            user_id = params.get("userId", [None])[0]
            if not user_id:
                self.send_json({"error": "Falta el usuario."}, 400)
                return

            state = get_user_state(user_id)
            if not state:
                self.send_json({"error": "Usuario no encontrado."}, 404)
            else:
                self.send_json(state)
            return

        if path == "/api/admin/status":
            with connect_db() as db:
                count = db.execute(
                    "SELECT COUNT(*) AS total FROM admins"
                ).fetchone()["total"]
            self.send_json({"configured": count > 0})
            return

        if path == "/api/admin/data":
            if not self.require_admin():
                return
            self.admin_data()
            return

        if path == "/api/admin/config":
            if not self.require_admin():
                return
            self.send_json({"config": get_config()})
            return

        if path == "/api/admin/finance":
            if not self.require_admin():
                return
            self.admin_finance()
            return

        if path == "/api/admin/security":
            if not self.require_admin():
                return
            self.admin_security()
            return

        super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        data = self.read_json()

        if data is None:
            self.send_json({"error": "Solicitud inválida."}, 400)
            return

        public_routes = {
            "/api/roblox/search",
            "/api/profile/confirm",
            "/api/surveys/complete",
            "/api/redeem",
            "/api/admin/setup",
            "/api/admin/login",
        }

        if path not in public_routes:
            session = self.require_admin(require_csrf=True)
            if not session:
                return
            self.current_admin_id = session["admin_id"]

        if path == "/api/roblox/search":
            self.roblox_search(data)
        elif path == "/api/profile/confirm":
            self.confirm_profile(data)
        elif path == "/api/surveys/complete":
            self.complete_survey(data)
        elif path == "/api/redeem":
            self.redeem(data)
        elif path == "/api/admin/setup":
            self.admin_setup(data)
        elif path == "/api/admin/login":
            self.admin_login(data)
        elif path == "/api/admin/logout":
            self.admin_logout()
        elif path == "/api/admin/rate":
            self.admin_rate(data)
        elif path == "/api/admin/request":
            self.admin_request(data)
        elif path == "/api/admin/config":
            self.admin_save_config(data)
        elif path == "/api/admin/finance":
            self.admin_add_finance(data)
        elif path == "/api/admin/ban":
            self.admin_ban(data)
        elif path == "/api/admin/unban":
            self.admin_unban(data)
        else:
            self.send_json({"error": "Ruta no encontrada."}, 404)

    # ========================================================
    # ROBLOX
    # ========================================================

    def roblox_search(self, data):
        username = str(data.get("username", "")).strip()

        if not username or len(username) > 20:
            self.send_json({"error": "Nombre de usuario inválido."}, 400)
            return

        payload = json.dumps({
            "usernames": [username],
            "excludeBannedUsers": True
        }).encode("utf-8")

        request = Request(
            "https://users.roblox.com/v1/usernames/users",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )

        try:
            with urlopen(request, timeout=10) as response:
                result = json.loads(response.read().decode("utf-8"))

            users = result.get("data", [])
            if not users:
                self.send_json({"error": "No encontramos ese usuario."}, 404)
                return

            user = users[0]
            user_id = str(user["id"])
            avatar = ""

            avatar_url = (
                "https://thumbnails.roblox.com/v1/users/avatar-headshot"
                f"?userIds={user_id}&size=150x150&format=Png&isCircular=false"
            )

            try:
                with urlopen(avatar_url, timeout=10) as response:
                    avatar_data = json.loads(response.read().decode("utf-8"))
                if avatar_data.get("data"):
                    avatar = avatar_data["data"][0].get("imageUrl", "")
            except Exception:
                pass

            self.send_json({
                "userId": user_id,
                "username": user.get("name", username),
                "displayName": user.get("displayName", username),
                "avatar": avatar,
                "verified": False,
                "message": "Perfil público encontrado. No demuestra propiedad."
            })

        except (HTTPError, URLError, TimeoutError):
            self.send_json({"error": "No pudimos conectar con Roblox."}, 502)

    def confirm_profile(self, data):
        user_id = str(data.get("userId", "")).strip()
        username = str(data.get("username", "")).strip()
        display_name = str(data.get("displayName", username)).strip()
        avatar = str(data.get("avatar", "")).strip()

        if not user_id.isdigit() or not username or len(username) > 30:
            self.send_json({"error": "Perfil inválido."}, 400)
            return

        if active_ban(user_id):
            self.send_json({"error": "Esta cuenta está bloqueada."}, 403)
            return

        # La búsqueda pública de Roblox NO es verificación de propiedad.
        with connect_db() as db:
            db.execute("""
                INSERT INTO users
                (user_id, username, display_name, avatar_url, created_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    username=excluded.username,
                    display_name=excluded.display_name,
                    avatar_url=excluded.avatar_url
            """, (user_id, username, display_name, avatar[:500], now()))

        self.send_json({
            "success": True,
            "state": get_user_state(user_id),
            "verified": False
        })

    # ========================================================
    # ACTIVIDADES DEMO
    # ========================================================

    def complete_survey(self, data):
        user_id = str(data.get("userId", "")).strip()
        survey_id = str(data.get("surveyId", "")).strip()

        if not user_id.isdigit():
            self.send_json({"error": "Usuario inválido."}, 400)
            return

        if active_ban(user_id):
            self.send_json({"error": "Cuenta bloqueada."}, 403)
            return

        survey = next(
            (x for x in SURVEYS if x["id"] == survey_id),
            None
        )

        if not survey:
            self.send_json({"error": "Actividad no válida."}, 400)
            return

        with connect_db() as db:
            user = db.execute(
                "SELECT * FROM users WHERE user_id=?",
                (user_id,)
            ).fetchone()

            if not user:
                self.send_json({"error": "Usuario no encontrado."}, 404)
                return

            try:
                db.execute("""
                    INSERT INTO completions
                    (user_id, survey_id, reward, completed_at)
                    VALUES (?, ?, ?, ?)
                """, (user_id, survey_id, survey["reward"], now()))
            except sqlite3.IntegrityError:
                self.send_json({"error": "Ya completaste esta actividad."}, 409)
                return

            db.execute("""
                UPDATE users
                SET balance=balance+?,
                    earned=earned+?,
                    completed=completed+1
                WHERE user_id=?
            """, (survey["reward"], survey["reward"], user_id))

            add_history(
                db, user_id,
                "Actividad demo: " + survey["title"],
                survey["reward"], "earned"
            )

        self.send_json({
            "success": True,
            "state": get_user_state(user_id)
        })

    # ========================================================
    # CANJES
    # ========================================================

    def redeem(self, data):
        user_id = str(data.get("userId", "")).strip()
        username = str(data.get("username", "")).strip()

        if not user_id.isdigit():
            self.send_json({"error": "Usuario inválido."}, 400)
            return

        if active_ban(user_id):
            self.send_json({"error": "Cuenta bloqueada."}, 403)
            return

        try:
            amount = int(data.get("amount", 0))
        except (ValueError, TypeError):
            self.send_json({"error": "Cantidad inválida."}, 400)
            return

        if amount < MIN_REDEEM or amount > MAX_REDEEM:
            self.send_json({
                "error": f"Los canjes deben ser de {MIN_REDEEM} a {MAX_REDEEM} Robux."
            }, 400)
            return

        rate = get_points_rate()
        if rate <= 0:
            self.send_json({"error": "Tasa inválida."}, 500)
            return

        points = int(round(amount * rate))

        with connect_db() as db:
            # Bloquea escrituras concurrentes para evitar doble gasto.
            db.execute("BEGIN IMMEDIATE")

            user = db.execute(
                "SELECT * FROM users WHERE user_id=?",
                (user_id,)
            ).fetchone()

            if not user:
                self.send_json({"error": "Usuario no encontrado."}, 404)
                return

            if user["balance"] < points:
                self.send_json({"error": "No tienes suficientes puntos."}, 400)
                return

            db.execute("""
                UPDATE users SET balance=balance-?
                WHERE user_id=? AND balance>=?
            """, (points, user_id, points))

            cursor = db.execute("""
                INSERT INTO requests
                (user_id, username, amount, points, status, created_at)
                VALUES (?, ?, ?, ?, 'pending', ?)
            """, (user_id, username[:30], amount, points, now()))

            add_history(
                db, user_id,
                f"Solicitud de canje de {amount} Robux",
                -points, "redeem"
            )

            request_id = cursor.lastrowid

        self.send_json({
            "success": True,
            "requestId": request_id,
            "state": get_user_state(user_id),
            "message": "Solicitud registrada y pendiente de revisión."
        })

    # ========================================================
    # CONFIGURACIÓN DEL ÚNICO ADMINISTRADOR
    # ========================================================

    def admin_setup(self, data):
        # El primer administrador solo se crea desde la computadora
        # donde está ejecutándose el servidor.
        if not self.local_request():
            self.send_json({"error": "Configuración inicial solo local."}, 403)
            return

        if not self.check_origin():
            self.send_json({"error": "Origen no permitido."}, 403)
            return

        email = str(data.get("email", "")).strip().lower()
        password = str(data.get("password", ""))

        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            self.send_json({"error": "Correo inválido."}, 400)
            return

        if len(password) < 16 or len(password) > 128:
            self.send_json({
                "error": "Usa una contraseña de entre 16 y 128 caracteres."
            }, 400)
            return

        with connect_db() as db:
            db.execute("BEGIN IMMEDIATE")

            count = db.execute(
                "SELECT COUNT(*) AS total FROM admins"
            ).fetchone()["total"]

            if count > 0:
                self.send_json({"error": "El administrador ya está configurado."}, 409)
                return

            salt = secrets.token_hex(32)
            digest = hash_password(password, salt)

            cursor = db.execute("""
                INSERT INTO admins
                (email, password_hash, salt, created_at)
                VALUES (?, ?, ?, ?)
            """, (email, digest, salt, now()))

            admin_id = cursor.lastrowid
            token, csrf = create_admin_session(db, admin_id)
            audit(db, admin_id, "admin_created", email)

        self.admin_cookie(token)
        self.send_json({
            "success": True,
            "csrfToken": csrf,
            "message": "Cuenta de propietario creada."
        })

    def admin_login(self, data):
        if not self.check_origin():
            self.send_json({"error": "Origen no permitido."}, 403)
            return

        email = str(data.get("email", "")).strip().lower()
        password = str(data.get("password", ""))

        if len(email) > 254 or len(password) > 128:
            self.send_json({"error": "Credenciales inválidas."}, 401)
            return

        with connect_db() as db:
            if self.login_locked(db):
                self.send_json({
                    "error": "Demasiados intentos. Intenta más tarde."
                }, 429)
                return

            admin = db.execute(
                "SELECT * FROM admins WHERE email=?",
                (email,)
            ).fetchone()

            if not admin:
                # Trabajo de hash ficticio para reducir diferencias de tiempo.
                hash_password(password or "invalid", "00" * 32)
                self.record_login_failure(db)
                time.sleep(0.5)
                self.send_json({"error": "Correo o contraseña incorrectos."}, 401)
                return

            calculated = hash_password(password, admin["salt"])

            if not hmac.compare_digest(calculated, admin["password_hash"]):
                self.record_login_failure(db)
                security_event(db, None, "admin_login_failed", "high", email)
                time.sleep(0.5)
                self.send_json({"error": "Correo o contraseña incorrectos."}, 401)
                return

            self.clear_login_failures(db)

            # Se invalidan las sesiones anteriores al iniciar una nueva.
            db.execute(
                "DELETE FROM admin_sessions WHERE admin_id=?",
                (admin["id"],)
            )

            token, csrf = create_admin_session(db, admin["id"])
            audit(db, admin["id"], "admin_login", email)

        self.admin_cookie(token)
        self.send_json({"success": True, "csrfToken": csrf})

    def admin_logout(self):
        token = self.get_admin_token()

        if token:
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            with connect_db() as db:
                db.execute(
                    "DELETE FROM admin_sessions WHERE token_hash=?",
                    (token_hash,)
                )
                audit(
                    db, getattr(self, "current_admin_id", None),
                    "admin_logout"
                )

        self.send_json(
            {"success": True},
            extra_headers=self.clear_admin_cookie()
        )

    # ========================================================
    # PANEL ADMINISTRATIVO
    # ========================================================

    def admin_data(self):
        with connect_db() as db:
            stats = db.execute("""
                SELECT COUNT(*) AS total_users,
                       COALESCE(SUM(balance),0) AS total_balance,
                       COALESCE(SUM(earned),0) AS total_earned,
                       COALESCE(SUM(completed),0) AS total_completed
                FROM users
            """).fetchone()

            request_counts = db.execute("""
                SELECT status, COUNT(*) AS total
                FROM requests GROUP BY status
            """).fetchall()

            requests = db.execute("""
                SELECT * FROM requests ORDER BY id DESC LIMIT 200
            """).fetchall()

            users = db.execute("""
                SELECT u.user_id, u.username, u.display_name,
                       u.balance, u.earned, u.completed, u.created_at,
                       CASE WHEN EXISTS (
                           SELECT 1 FROM user_bans b
                           WHERE b.user_id=u.user_id AND b.active=1
                           AND (b.expires_at IS NULL OR b.expires_at > ?)
                       ) THEN 1 ELSE 0 END AS banned
                FROM users u
                ORDER BY u.created_at DESC LIMIT 200
            """, (now(),)).fetchall()

        self.send_json({
            "stats": dict(stats),
            "requestCounts": [dict(x) for x in request_counts],
            "requests": [dict(x) for x in requests],
            "users": [dict(x) for x in users],
            "pointsRate": get_points_rate()
        })

    def admin_request(self, data):
        try:
            request_id = int(data.get("requestId"))
        except (ValueError, TypeError):
            self.send_json({"error": "Solicitud inválida."}, 400)
            return

        action = str(data.get("action", ""))
        if action not in ("approve", "reject"):
            self.send_json({"error": "Acción inválida."}, 400)
            return

        with connect_db() as db:
            db.execute("BEGIN IMMEDIATE")
            request = db.execute(
                "SELECT * FROM requests WHERE id=?",
                (request_id,)
            ).fetchone()

            if not request:
                self.send_json({"error": "Solicitud no encontrada."}, 404)
                return

            if request["status"] != "pending":
                self.send_json({"error": "Solicitud ya procesada."}, 409)
                return

            status = "approved" if action == "approve" else "rejected"
            db.execute(
                "UPDATE requests SET status=? WHERE id=? AND status='pending'",
                (status, request_id)
            )

            if action == "reject":
                db.execute("""
                    UPDATE users SET balance=balance+?
                    WHERE user_id=?
                """, (request["points"], request["user_id"]))

                add_history(
                    db, request["user_id"],
                    "Canje rechazado: puntos devueltos",
                    request["points"], "refund"
                )

            audit(
                db, self.current_admin_id,
                "redeem_" + action, request_id,
                f"Usuario {request['user_id']}; cantidad {request['amount']}"
            )

        self.send_json({"success": True})

    def admin_rate(self, data):
        try:
            rate = float(data.get("rate"))
        except (ValueError, TypeError):
            self.send_json({"error": "Tasa inválida."}, 400)
            return

        if not 0 < rate <= 1000:
            self.send_json({"error": "Tasa fuera de rango."}, 400)
            return

        save_setting("points_rate", rate)

        with connect_db() as db:
            audit(db, self.current_admin_id, "change_points_rate", "", str(rate))

        self.send_json({"success": True, "rate": rate})

    # ========================================================
    # BANEOS Y SEGURIDAD
    # ========================================================

    def admin_ban(self, data):
        user_id = str(data.get("userId", "")).strip()
        reason = str(data.get("reason", "")).strip()
        duration = str(data.get("duration", ""))

        durations = {
            "24h": timedelta(hours=24),
            "7d": timedelta(days=7),
            "30d": timedelta(days=30),
            "permanent": None
        }

        if not user_id.isdigit() or duration not in durations or not reason:
            self.send_json({"error": "Datos de bloqueo inválidos."}, 400)
            return

        expires = None
        if durations[duration]:
            expires = (
                datetime.now(timezone.utc) + durations[duration]
            ).isoformat()

        with connect_db() as db:
            db.execute("""
                UPDATE user_bans SET active=0
                WHERE user_id=? AND active=1
            """, (user_id,))

            db.execute("""
                INSERT INTO user_bans
                (user_id, reason, duration, created_at, expires_at, active, created_by)
                VALUES (?, ?, ?, ?, ?, 1, ?)
            """, (
                user_id, reason[:500], duration, now(),
                expires, self.current_admin_id
            ))

            security_event(
                db, user_id, "admin_ban", "high",
                f"{duration}: {reason}"
            )
            audit(
                db, self.current_admin_id,
                "ban_user", user_id,
                f"{duration}: {reason}"
            )

        self.send_json({"success": True})

    def admin_unban(self, data):
        user_id = str(data.get("userId", "")).strip()

        if not user_id.isdigit():
            self.send_json({"error": "Usuario inválido."}, 400)
            return

        with connect_db() as db:
            cursor = db.execute("""
                UPDATE user_bans
                SET active=0, revoked_at=?
                WHERE user_id=? AND active=1
            """, (now(), user_id))

            if cursor.rowcount == 0:
                self.send_json({"error": "No hay un bloqueo activo."}, 404)
                return

            security_event(db, user_id, "admin_unban", "info", "Desbloqueo manual")
            audit(db, self.current_admin_id, "unban_user", user_id)

        self.send_json({"success": True})

    def admin_security(self):
        with connect_db() as db:
            bans = db.execute("""
                SELECT * FROM user_bans
                ORDER BY id DESC LIMIT 200
            """).fetchall()

            events = db.execute("""
                SELECT * FROM security_events
                ORDER BY id DESC LIMIT 200
            """).fetchall()

            logs = db.execute("""
                SELECT * FROM admin_audit
                ORDER BY id DESC LIMIT 200
            """).fetchall()

        self.send_json({
            "bans": [dict(x) for x in bans],
            "events": [dict(x) for x in events],
            "audit": [dict(x) for x in logs]
        })

    # ========================================================
    # PERSONALIZACIÓN
    # ========================================================

    def admin_save_config(self, data):
        allowed_themes = {
            "original", "halloween", "christmas",
            "valentines", "easter", "independence"
        }

        mode = data.get("theme_mode", "auto")
        manual_theme = data.get("manual_theme", "original")

        if mode not in ("auto", "manual", "disabled"):
            self.send_json({"error": "Modo de tema inválido."}, 400)
            return

        if manual_theme not in allowed_themes:
            self.send_json({"error": "Tema inválido."}, 400)
            return

        schedule = data.get(
            "festival_schedule",
            DEFAULT_CONFIG["festival_schedule"]
        )

        if not isinstance(schedule, dict):
            self.send_json({"error": "Calendario inválido."}, 400)
            return

        for theme, dates in schedule.items():
            if theme not in allowed_themes or theme == "original":
                self.send_json({"error": "Tema de calendario inválido."}, 400)
                return

            if (
                not isinstance(dates, list)
                or len(dates) != 2
                or not all(
                    isinstance(x, str)
                    and re.fullmatch(r"\d{2}-\d{2}", x)
                    for x in dates
                )
            ):
                self.send_json({"error": "Formato de fecha inválido."}, 400)
                return

        fields = {
            "theme_mode": mode,
            "manual_theme": manual_theme,
            "festival_schedule": schedule,
            "hero_title": str(data.get("hero_title", ""))[:150],
            "hero_highlight": str(data.get("hero_highlight", ""))[:100],
            "hero_subtitle": str(data.get("hero_subtitle", ""))[:300],
            "announcement": str(data.get("announcement", ""))[:500],
        }

        for key, value in fields.items():
            save_setting(key, value)

        with connect_db() as db:
            audit(db, self.current_admin_id, "save_site_config")

        self.send_json({"success": True, "config": get_config()})

    # ========================================================
    # FINANZAS
    # ========================================================

    def admin_finance(self):
        with connect_db() as db:
            totals = db.execute("""
                SELECT
                    COALESCE(SUM(CASE WHEN entry_type='income'
                        THEN amount ELSE 0 END),0) AS income,
                    COALESCE(SUM(CASE WHEN entry_type='expense'
                        THEN amount ELSE 0 END),0) AS expenses
                FROM finance_entries
            """).fetchone()

            liabilities = db.execute("""
                SELECT COALESCE(SUM(balance),0) AS total
                FROM users
            """).fetchone()["total"]

            entries = db.execute("""
                SELECT * FROM finance_entries
                ORDER BY id DESC LIMIT 200
            """).fetchall()

        income = float(totals["income"])
        expenses = float(totals["expenses"])

        self.send_json({
            "income": income,
            "expenses": expenses,
            "profit": income - expenses,
            "userPointsLiability": liabilities,
            "entries": [dict(x) for x in entries]
        })

    def admin_add_finance(self, data):
        entry_type = str(data.get("type", ""))

        if entry_type not in ("income", "expense"):
            self.send_json({"error": "Tipo inválido."}, 400)
            return

        try:
            amount = float(data.get("amount"))
        except (ValueError, TypeError):
            self.send_json({"error": "Cantidad inválida."}, 400)
            return

        if not 0 < amount <= 1_000_000:
            self.send_json({"error": "Cantidad fuera de rango."}, 400)
            return

        note = str(data.get("note", ""))[:300]

        with connect_db() as db:
            db.execute("""
                INSERT INTO finance_entries
                (entry_type, amount, note, created_at)
                VALUES (?, ?, ?, ?)
            """, (entry_type, amount, note, now()))

            audit(
                db, self.current_admin_id,
                "finance_entry", "",
                f"{entry_type}: {amount}; {note}"
            )

        self.send_json({"success": True})


# ============================================================
# INICIO
# ============================================================

# ============================================================
# INICIO
# ============================================================

# ============================================================
# INICIO
# ============================================================

if __name__ == "__main__":
    initialize_database()

    # Lee el puerto dinámico que asigna Render, o usa 8000 si estás en tu PC local
    port = int(os.environ.get("PORT", 8000))

    server = ThreadingHTTPServer(
        ("0.0.0.0", port),
        RbxQuestlyHandler
    )

    print("")
    print("======================================")
    print("       RBXQUESTLY ESTÁ INICIADO")
    print("======================================")
    print(f"Página: http://0.0.0.0:{port}")
    print("Para detener: CTRL + C")
    print("======================================")
    print("")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nCerrando RbxQuestly...")
    finally:
        server.server_close()
        # Variable para el control manual del diseño/temporada desde el Admin
active_season_config = "original"

@app.route('/api/admin/set-season', methods=['POST'])
def set_season():
    global active_season_config
    data = request.json
    season = data.get('season', 'original')
    active_season_config = season
    return {"status": "success", "active_season": active_season_config}

@app.route('/api/admin/get-season', methods=['GET'])
def get_season():
    global active_season_config
    return {"active_season": active_season_config}
