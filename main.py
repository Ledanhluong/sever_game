import os
import re
import json
import time
import hmac
import hashlib
import sqlite3
import jwt
import psycopg
from psycopg.rows import dict_row
from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

app = FastAPI(title="Tu Tien Game Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = os.getenv("SECRET_KEY", "doi_chuoi_bi_mat_nay_khi_dua_len_server_2026")
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
DB_PATH = "game_server.db"

login_attempts: dict[str, list[float]] = {}

def dung_postgres() -> bool:
    return DATABASE_URL.startswith("postgres://") or DATABASE_URL.startswith("postgresql://")

def get_db():
    if dung_postgres():
        url = DATABASE_URL.replace("postgres://", "postgresql://", 1)
        return psycopg.connect(url, row_factory=dict_row)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    if dung_postgres():
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    selected_character TEXT DEFAULT 'cha1',
                    level INTEGER DEFAULT 1,
                    vang INTEGER DEFAULT 1000,
                    da_quy INTEGER DEFAULT 100,
                    game_data TEXT DEFAULT '{}',
                    updated_at DOUBLE PRECISION DEFAULT 0,
                    created_at DOUBLE PRECISION
                )
            """)
            # Tự động thêm cột nếu bảng users đã tồn tại từ bản cũ
            cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS game_data TEXT DEFAULT '{}'")
            cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at DOUBLE PRECISION DEFAULT 0")
        conn.commit()
    else:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                selected_character TEXT DEFAULT 'cha1',
                level INTEGER DEFAULT 1,
                vang INTEGER DEFAULT 1000,
                da_quy INTEGER DEFAULT 100,
                game_data TEXT DEFAULT '{}',
                updated_at REAL DEFAULT 0,
                created_at REAL
            )
        """)
        conn.commit()
    conn.close()

init_db()

def hash_password(password: str, salt_hex: str | None = None) -> tuple[str, str]:
    salt = bytes.fromhex(salt_hex) if salt_hex else os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120_000)
    return pwd_hash.hex(), salt.hex()

def verify_password(password: str, stored_hash: str, salt_hex: str) -> bool:
    check_hash, _ = hash_password(password, salt_hex)
    return hmac.compare_digest(check_hash, stored_hash)

def validate_username(username: str) -> str | None:
    if not username:
        return "Tên đăng nhập không được để trống!"
    if " " in username:
        return "Tên đăng nhập không được chứa dấu cách!"
    if not re.fullmatch(r"[A-Za-z0-9]+", username):
        return "Tên đăng nhập chỉ được gồm chữ và số, không dấu cách!"
    if not (re.search(r"[A-Za-z]", username) and re.search(r"[0-9]", username)):
        return "Tên đăng nhập phải bao gồm cả chữ và số!"
    if len(username) < 4 or len(username) > 24:
        return "Tên đăng nhập phải từ 4 đến 24 ký tự!"
    return None

def check_rate_limit(client_ip: str):
    now = time.time()
    history = [t for t in login_attempts.get(client_ip, []) if now - t < 60.0]
    if len(history) >= 5:
        raise HTTPException(status_code=429, detail={"message": "Thử sai quá nhiều lần, vui lòng đợi 1 phút!"})
    history.append(now)
    login_attempts[client_ip] = history

def decode_user_from_header(authorization: str) -> dict:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail={"message": "Thiếu token xác thực!"})
    token = authorization.removeprefix("Bearer ").strip()
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail={"message": "Phiên đăng nhập hết hạn hoặc không hợp lệ!"})

def format_player_data(row: dict) -> dict:
    raw_extra = row.get("game_data") or "{}"
    try:
        extra_dict = json.loads(raw_extra) if isinstance(raw_extra, str) else dict(raw_extra)
    except Exception:
        extra_dict = {}
    return {
        "username": row["username"],
        "selected_character": row["selected_character"],
        "level": row["level"],
        "vang": row["vang"],
        "da_quy": row["da_quy"],
        "game_data": extra_dict
    }

class AuthPayload(BaseModel):
    username: str
    password: str

class SyncPayload(BaseModel):
    selected_character: str = "cha1"
    level: int = Field(ge=1, le=9999)
    vang: int = Field(ge=0, le=2_000_000_000)
    da_quy: int = Field(ge=0, le=100_000_000)
    game_data: dict = Field(default_factory=dict)

@app.get("/")
@app.head("/")
def health_check():
    return {
        "status": "online",
        "database": "postgresql" if dung_postgres() else "sqlite",
        "message": "Server game đang hoạt động"
    }

@app.post("/register")
def register(payload: AuthPayload):
    err = validate_username(payload.username)
    if err:
        raise HTTPException(status_code=400, detail={"message": err})
    if len(payload.password) < 4:
        raise HTTPException(status_code=400, detail={"message": "Mật khẩu phải có ít nhất 4 ký tự!"})

    pwd_hash, salt_hex = hash_password(payload.password)
    now = time.time()
    conn = get_db()
    try:
        if dung_postgres():
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO users (username, password_hash, salt, updated_at, created_at) VALUES (%s, %s, %s, %s, %s)",
                    (payload.username, pwd_hash, salt_hex, now, now)
                )
            conn.commit()
        else:
            conn.execute(
                "INSERT INTO users (username, password_hash, salt, updated_at, created_at) VALUES (?, ?, ?, ?, ?)",
                (payload.username, pwd_hash, salt_hex, now, now)
            )
            conn.commit()
    except Exception as e:
        if "unique" in str(e).lower() or "integrity" in str(e).lower():
            raise HTTPException(status_code=409, detail={"message": "Tên đăng nhập đã tồn tại!"})
        raise HTTPException(status_code=500, detail={"message": "Lỗi cơ sở dữ liệu!"})
    finally:
        conn.close()

    return {"ok": True, "message": "Đăng ký thành công!"}

@app.post("/login")
def login(payload: AuthPayload, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    check_rate_limit(client_ip)

    conn = get_db()
    if dung_postgres():
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE username = %s", (payload.username,))
            row = cur.fetchone()
    else:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (payload.username,)).fetchone()
    conn.close()

    if row is None:
        raise HTTPException(status_code=401, detail={"message": "Sai tên đăng nhập!"})

    row_dict = dict(row)
    if not verify_password(payload.password, row_dict["password_hash"], row_dict["salt"]):
        raise HTTPException(status_code=401, detail={"message": "Sai mật khẩu!"})

    login_attempts.pop(client_ip, None)

    token = jwt.encode(
        {
            "uid": row_dict["id"],
            "username": row_dict["username"],
            "exp": int(time.time()) + 7 * 86400
        },
        SECRET_KEY,
        algorithm="HS256"
    )

    return {
        "ok": True,
        "message": "Đăng nhập thành công!",
        "token": token,
        "player_data": format_player_data(row_dict)
    }

@app.get("/me")
def get_my_profile(authorization: str = Header(default="")):
    decoded = decode_user_from_header(authorization)

    conn = get_db()
    if dung_postgres():
        with conn.cursor() as cur:
            cur.execute(
                "SELECT username, selected_character, level, vang, da_quy, game_data FROM users WHERE id = %s",
                (decoded["uid"],)
            )
            row = cur.fetchone()
    else:
        row = conn.execute(
            "SELECT username, selected_character, level, vang, da_quy, game_data FROM users WHERE id = ?",
            (decoded["uid"],)
        ).fetchone()
    conn.close()

    if row is None:
        raise HTTPException(status_code=404, detail={"message": "Không tìm thấy người chơi!"})

    return {"ok": True, "player_data": format_player_data(dict(row))}

@app.post("/sync")
def sync_player_data(payload: SyncPayload, authorization: str = Header(default="")):
    decoded = decode_user_from_header(authorization)
    uid = decoded["uid"]

    conn = get_db()
    if dung_postgres():
        with conn.cursor() as cur:
            cur.execute("SELECT level, vang, da_quy FROM users WHERE id = %s", (uid,))
            current = cur.fetchone()
    else:
        current = conn.execute("SELECT level, vang, da_quy FROM users WHERE id = ?", (uid,)).fetchone()

    if current is None:
        conn.close()
        raise HTTPException(status_code=404, detail={"message": "Không tìm thấy người chơi!"})

    cur_dict = dict(current)
    # Kiểm tra chống hack chỉ số tăng đột biến bất thường trong 1 lần sync
    if payload.vang - cur_dict["vang"] > 50_000_000 or payload.da_quy - cur_dict["da_quy"] > 500_000:
        conn.close()
        raise HTTPException(status_code=400, detail={"message": "Phát hiện biến động tài nguyên bất thường!"})
    if payload.level < cur_dict["level"] or payload.level - cur_dict["level"] > 50:
        conn.close()
        raise HTTPException(status_code=400, detail={"message": "Cấp độ không hợp lệ!"})

    extra_json = json.dumps(payload.game_data, ensure_ascii=False)
    now = time.time()

    if dung_postgres():
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE users
                SET selected_character = %s, level = %s, vang = %s, da_quy = %s, game_data = %s, updated_at = %s
                WHERE id = %s
                """,
                (payload.selected_character, payload.level, payload.vang, payload.da_quy, extra_json, now, uid)
            )
        conn.commit()
    else:
        conn.execute(
            """
            UPDATE users
            SET selected_character = ?, level = ?, vang = ?, da_quy = ?, game_data = ?, updated_at = ?
            WHERE id = ?
            """,
            (payload.selected_character, payload.level, payload.vang, payload.da_quy, extra_json, now, uid)
        )
        conn.commit()
    conn.close()

    return {"ok": True, "message": "Đã đồng bộ dữ liệu lên máy chủ!", "updated_at": now}
